package executor

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// maxUpstreamBytes bounds one response from Grafana, so that a broad query cannot
// use up the proxy's memory before the reducers run.
const maxUpstreamBytes = 32 << 20

// errUpstreamTooLarge is the read error of a response above maxUpstreamBytes.
var errUpstreamTooLarge = errors.New("the Grafana response is too large")

// readOnlyTransport is a read-only layer below grafana-mcp. It pins the Grafana
// host and allows only GET, plus POST on the query path. One instance serves all
// requests of a call and remembers what happened, so that a failure is named from
// the HTTP status and not from upstream's words.
type readOnlyTransport struct {
	next      http.RoundTripper
	scheme    string
	host      string
	queryPath string

	mu         sync.Mutex
	lastStatus int
	refused    bool
	tooLarge   bool
	transport  bool
}

// RoundTrip implements http.RoundTripper.
func (t *readOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != t.scheme || request.URL.Host != t.host {
		t.remember(func() { t.refused = true })
		return nil, fmt.Errorf("the proxy talks only to its own Grafana, not to %s", request.URL.Host)
	}
	allowed := request.Method == http.MethodGet || (request.Method == http.MethodPost && request.URL.Path == t.queryPath)
	if !allowed {
		t.remember(func() { t.refused = true })
		return nil, fmt.Errorf("the proxy only reads: %s %s was refused", request.Method, request.URL.Path)
	}
	response, err := t.next.RoundTrip(request)
	if err != nil {
		t.remember(func() { t.transport = true })
		return nil, err
	}
	t.remember(func() { t.lastStatus = response.StatusCode })
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		_ = response.Body.Close()
		t.remember(func() { t.refused = true })
		return nil, fmt.Errorf("the proxy does not follow redirects: %d from %s", response.StatusCode, request.URL.Path)
	}
	response.Body = &limitedBody{ReadCloser: response.Body, remaining: maxUpstreamBytes, onTooLarge: func() {
		t.remember(func() { t.tooLarge = true })
	}}
	return response, nil
}

func (t *readOnlyTransport) remember(change func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	change()
}

// outcome is what one call saw on the wire.
type outcome struct {
	lastStatus int
	refused    bool
	tooLarge   bool
	transport  bool
}

func (t *readOnlyTransport) outcome() outcome {
	t.mu.Lock()
	defer t.mu.Unlock()
	return outcome{lastStatus: t.lastStatus, refused: t.refused, tooLarge: t.tooLarge, transport: t.transport}
}

type limitedBody struct {
	io.ReadCloser
	remaining  int64
	onTooLarge func()
}

// Read implements io.Reader. It fails once the body passes the limit, so that a
// caller cannot take the first part of a large response for all of it.
func (b *limitedBody) Read(buffer []byte) (int, error) {
	if b.remaining < 0 {
		return 0, errUpstreamTooLarge
	}
	if int64(len(buffer)) > b.remaining+1 {
		buffer = buffer[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(buffer)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		b.onTooLarge()
		return 0, errUpstreamTooLarge
	}
	return n, err
}

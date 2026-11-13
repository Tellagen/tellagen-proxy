package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// readyWindow is how recent the last answer from Tellagen must be for /readyz.
const readyWindow = 60 * time.Second

// Status is what /readyz reports. The doctor reads it from a running proxy.
type Status struct {
	Ready      bool     `json:"ready"`
	Version    string   `json:"version"`
	Mode       string   `json:"mode"`
	Degraded   bool     `json:"degraded"`
	WaitingFor []string `json:"waiting_for,omitempty"`
	Blocked    string   `json:"blocked,omitempty"`
	LastError  string   `json:"last_error,omitempty"`
	// LastContactAgeS is the age of the last answer from Tellagen, or -1.
	LastContactAgeS int `json:"last_contact_age_s"`
}

// state is the live state behind /readyz and the metrics.
type state struct {
	now     func() time.Time
	version string

	mu        sync.Mutex
	lastOK    time.Time
	mode      string
	degraded  bool
	waiting   []string
	blocked   string
	lastError string
}

func (s *state) snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := Status{Version: s.version, Mode: s.mode, Degraded: s.degraded, WaitingFor: s.waiting, Blocked: s.blocked, LastError: s.lastError, LastContactAgeS: -1}
	if !s.lastOK.IsZero() {
		age := s.now().Sub(s.lastOK)
		status.LastContactAgeS = int(age / time.Second)
		status.Ready = age <= readyWindow && s.blocked == "" && len(s.waiting) == 0
	}
	return status
}

func (s *state) contact() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastOK, s.blocked, s.lastError = s.now(), "", ""
}

func (s *state) setMode(mode string, degraded bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode, s.degraded = mode, degraded
}

func (s *state) setWaiting(files []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waiting = files
}

func (s *state) setBlocked(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked = reason
}

func (s *state) setError(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = message
}

// metrics are the proxy's own Prometheus series, on a private registry so that
// nothing from the linked libraries shows up.
type metrics struct {
	registry   *prometheus.Registry
	reconnects *prometheus.CounterVec
	transport  *prometheus.GaugeVec
	commands   *prometheus.CounterVec
	duration   prometheus.Histogram
}

func newMetrics(version string, st *state) *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		reconnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tellagen_proxy_reconnects_total", Help: "Polls that failed, by reason.",
		}, []string{"reason"}),
		transport: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tellagen_proxy_transport", Help: "1 for the poll mode in use.",
		}, []string{"mode"}),
		commands: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tellagen_proxy_jobs_total", Help: "Commands run, by result status.",
		}, []string{"status"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "tellagen_proxy_job_duration_seconds", Help: "Time to run one command.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 60},
		}),
	}
	connected := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tellagen_proxy_connected", Help: "1 when Tellagen answered in the last 60 seconds.",
	}, func() float64 {
		if st.snapshot().Ready {
			return 1
		}
		return 0
	})
	build := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tellagen_proxy_build_info", Help: "The version of this proxy.", ConstLabels: prometheus.Labels{"version": version},
	})
	build.Set(1)
	m.registry.MustRegister(connected, m.reconnects, m.transport, m.commands, m.duration, build)
	return m
}

func (m *metrics) setMode(mode string) {
	for _, known := range []string{protocol.PollModeLong, protocol.PollModeShort} {
		value := 0.0
		if known == mode {
			value = 1
		}
		m.transport.WithLabelValues(known).Set(value)
	}
}

// healthHandler serves the only three routes the proxy exposes. /healthz never
// looks at the network, so a Tellagen outage does not restart a pod.
func healthHandler(st *state, m *metrics) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		status := st.snapshot()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if !status.Ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(status)
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	return mux
}

// serveHealth serves on the listener until ctx ends.
func serveHealth(ctx context.Context, listener net.Listener, handler http.Handler) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

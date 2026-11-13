package doctor

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// connect sends a CONNECT request on conn and returns the proxy's status code.
func connect(ctx context.Context, conn net.Conn, address string, user *url.Userinfo) (int, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: http.Header{}}
	if user != nil {
		password, _ := user.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user.Username()+":"+password)))
	}
	if err := request.Write(conn); err != nil {
		return 0, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		return 0, fmt.Errorf("read the proxy's answer: %w", err)
	}
	_ = response.Body.Close()
	return response.StatusCode, nil
}

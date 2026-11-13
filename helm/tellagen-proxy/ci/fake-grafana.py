"""A fake Grafana for the kind test: the few calls the proxy doctor makes."""
import http.server
import json

ROUTES = {
    "/api/health": {"database": "ok", "version": "12.2.1"},
    "/api/user": {"login": "sa-tellagen-proxy"},
    "/api/org": {"id": 1, "name": "Main Org."},
    "/api/user/orgs": [{"orgId": 1, "role": "Viewer"}],
    "/api/datasources": [{"uid": "prom", "name": "Prometheus", "type": "prometheus", "isDefault": True}],
    "/api/datasources/proxy/uid/prom/api/v1/query": {"status": "success", "data": {"resultType": "vector", "result": []}},
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ROUTES.get(self.path.split("?")[0])
        if body is None:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("", 3000), Handler).serve_forever()

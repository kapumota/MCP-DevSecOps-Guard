import http.client
import threading

from devsecops_agent.app import Handler, NoReverseDnsHTTPServer


def test_health_endpoint():
    """Prueba de integración mínima del endpoint /health sin depender de subprocesos."""
    server = NoReverseDnsHTTPServer(("127.0.0.1", 0), Handler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        conn = http.client.HTTPConnection(host, port, timeout=3)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()

        assert resp.status == 200
        assert "saludable" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

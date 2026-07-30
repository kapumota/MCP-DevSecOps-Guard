"""Microservicio HTTP mínimo usado por el laboratorio DevSecOps."""

from __future__ import annotations

import json
import os
import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

DEFAULT_PORT = 8000
SERVICE_NAME = os.environ.get("SERVICE_NAME", "python-microservice")


def get_port() -> int:
    """Obtiene el puerto HTTP desde la variable de entorno PORT."""
    raw_port = os.environ.get("PORT", str(DEFAULT_PORT))
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError(f"PORT debe ser un entero válido, recibido: {raw_port!r}") from exc

    if not 1 <= port <= 65_535:
        raise ValueError(f"PORT debe estar entre 1 y 65535, recibido: {port}")
    return port


class NoReverseDnsHTTPServer(HTTPServer):
    """Servidor HTTP que evita búsquedas DNS inversas durante el bind."""

    allow_reuse_address = True

    def server_bind(self) -> None:
        """Asocia el socket sin depender de resolución DNS inversa."""
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


class Handler(BaseHTTPRequestHandler):
    """Manejador HTTP del microservicio."""

    server_version = "DevSecOpsLabHTTP/1.0"

    def _send_response(
        self,
        status_code: int,
        payload: dict[str, Any] | bytes | bytearray,
        content_type: str = "application/json",
    ) -> None:
        """Envía una respuesta HTTP con longitud y tipo de contenido explícitos."""
        # El servidor acepta payload binario o diccionarios serializables a JSON.
        if isinstance(payload, bytes | bytearray):
            body = bytes(payload)
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        # Las cabeceras explícitas hacen que healthchecks y pruebas sean deterministas.
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Mantiene el logging básico de la librería estándar, pero con prefijo estable."""
        # Se conserva logging a stderr para que Docker/Kubernetes puedan capturarlo.
        super().log_message("[devsecops-lab] " + format, *args)

    def do_GET(self) -> None:
        """Atiende los endpoints públicos del microservicio."""
        if self.path == "/":
            # Endpoint raíz: útil para verificar identidad del servicio.
            self._send_response(200, {"service": SERVICE_NAME, "ok": True})
            return

        if self.path == "/health":
            # Endpoint de salud usado por Docker, Kubernetes y pruebas de humo.
            self._send_response(200, {"status": "saludable"})
            return

        if self.path == "/ready":
            # Endpoint de disponibilidad usado por Kubernetes.
            self._send_response(200, {"status": "listo"})
            return

        # Cualquier ruta no registrada responde 404 sin exponer detalles internos.
        self._send_response(404, {"error": "ruta no encontrada"})


def main() -> None:
    """Inicia el servidor HTTP en 0.0.0.0 usando el puerto configurado."""
    port = get_port()
    server = NoReverseDnsHTTPServer(("0.0.0.0", port), Handler)
    print(f"Sirviendo '{SERVICE_NAME}' en http://0.0.0.0:{port} (CTRL+C para detener)")

    try:
        # El proceso queda bloqueado aquí hasta recibir una interrupción externa.
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido por KeyboardInterrupt.")
    finally:
        # Cierre explícito para liberar el socket de forma ordenada.
        server.server_close()
        print("Servidor apagado correctamente.")


if __name__ == "__main__":
    main()

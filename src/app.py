"""Compatibilidad temporal: ejecuta el microservicio desde el paquete real."""

from devsecops_agent.app import Handler, NoReverseDnsHTTPServer, get_port, main

__all__ = ["Handler", "NoReverseDnsHTTPServer", "get_port", "main"]

if __name__ == "__main__":
    main()

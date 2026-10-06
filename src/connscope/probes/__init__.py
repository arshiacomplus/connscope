from connscope.core.registry import ProbeRegistry

def register_builtin_probes(registry: ProbeRegistry) -> None:
    from .tcp_connect import TcpConnectProbe
    from .dns_resolve import DnsResolveProbe
    from .tls_handshake import TlsHandshakeProbe
    from .http_request import HttpRequestProbe

    registry.register(TcpConnectProbe())
    registry.register(DnsResolveProbe())
    registry.register(TlsHandshakeProbe())
    registry.register(HttpRequestProbe())

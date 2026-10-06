from connscope.core import ProbeRegistry, ProbeEngine
from connscope.probes import register_builtin_probes

def test_register_builtin_probes():
    registry = ProbeRegistry()
    register_builtin_probes(registry)
    
    names = registry.names()
    assert "tcp_connect" in names
    assert "dns_resolve" in names
    assert "tls_handshake" in names
    assert "http_request" in names
    
    # Verify engine can resolve them
    engine = ProbeEngine(registry=registry)
    
    tcp_probe = engine.registry.get("tcp_connect")
    assert tcp_probe.name == "tcp_connect"
    
    dns_probe = engine.registry.get("dns_resolve")
    assert dns_probe.name == "dns_resolve"
    
    tls_probe = engine.registry.get("tls_handshake")
    assert tls_probe.name == "tls_handshake"
    
    http_probe = engine.registry.get("http_request")
    assert http_probe.name == "http_request"

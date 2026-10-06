import asyncio
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from connscope.core import Probe, ProbeResult, ProbeStatus, Target

class TlsHandshakeProbe(Probe):
    name = "tls_handshake"

    async def run(
        self,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ProbeResult:
        timeout_s = float((config or {}).get("timeout_s", 10.0))
        started_at = datetime.now(timezone.utc)
        start_time = time.monotonic()
        
        # 443 is typical, but we respect target.port if given.
        port = target.port if target.port is not None else 443
        
        try:
            # 1. TCP Connect
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, port),
                timeout=timeout_s
            )
            
            connect_end_time = time.monotonic()
            connect_ms = (connect_end_time - start_time) * 1000.0
            
            # 2. TLS Handshake
            ssl_context = ssl.create_default_context()
            
            # Allow skipping verification for testing or local endpoints if configured
            if (config or {}).get("verify", True) is False:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_running_loop()
            
            # Calculate remaining timeout for handshake
            remaining_timeout = timeout_s - (connect_end_time - start_time)
            if remaining_timeout <= 0:
                raise asyncio.TimeoutError()
            
            # Wrap the existing connection in TLS
            transport = writer.transport
            protocol = transport.get_protocol()
            
            # Wait for handshake
            new_transport = await asyncio.wait_for(
                loop.start_tls(transport, protocol, ssl_context, server_hostname=target.host),
                timeout=remaining_timeout
            )
            
            handshake_end_time = time.monotonic()
            handshake_ms = (handshake_end_time - connect_end_time) * 1000.0
            total_ms = (handshake_end_time - start_time) * 1000.0
            
            # Extract details
            ssl_object = new_transport.get_extra_info("ssl_object")
            details = {}
            if ssl_object:
                details["tls_version"] = ssl_object.version()
                details["cipher"] = ssl_object.cipher()[0] if ssl_object.cipher() else None
                cert = ssl_object.getpeercert()
                if cert:
                    # simplistic extraction of CN from subject
                    subject = dict(x[0] for x in cert.get("subject", []))
                    details["cert_subject"] = subject.get("commonName")
            
            # Clean up
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
                
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=started_at,
                duration_ms=total_ms,
                metrics={
                    "connect_ms": connect_ms,
                    "handshake_ms": handshake_ms,
                    "total_ms": total_ms
                },
                details=details,
            )
            
        except asyncio.TimeoutError:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.TIMEOUT,
                started_at=started_at,
                duration_ms=duration_ms,
                error=f"Operation timed out after {timeout_s}s",
            )
        except ssl.SSLError as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            
            # Attempt to ensure the writer is closed if we got that far
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
                
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                error=f"TLS handshake failed: {str(e)}",
            )
        except OSError as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                error=f"TCP connection failed: {str(e)}",
            )

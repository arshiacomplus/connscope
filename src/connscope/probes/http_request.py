import asyncio
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from connscope.core import Probe, ProbeResult, ProbeStatus, Target

class HttpRequestProbe(Probe):
    name = "http_request"

    async def run(
        self,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ProbeResult:
        timeout_s = float((config or {}).get("timeout_s", 10.0))
        started_at = datetime.now(timezone.utc)
        start_time = time.monotonic()
        
        # Determine port and TLS
        use_tls = (config or {}).get("use_tls", True)
        port = target.port if target.port is not None else (443 if use_tls else 80)
        
        writer = None
        try:
            # 1. Connect (and TLS handshake if needed)
            if use_tls:
                ssl_context = ssl.create_default_context()
                if (config or {}).get("verify", True) is False:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
            else:
                ssl_context = None

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, port, ssl=ssl_context),
                timeout=timeout_s
            )
            
            connect_end_time = time.monotonic()
            connect_ms = (connect_end_time - start_time) * 1000.0
            
            # 2. Send HTTP Request
            path = (config or {}).get("path", "/")
            method = (config or {}).get("method", "GET")
            
            request = f"{method} {path} HTTP/1.1\r\nHost: {target.host}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode("utf-8"))
            await writer.drain()
            
            # Calculate remaining timeout
            remaining_timeout = timeout_s - (time.monotonic() - start_time)
            if remaining_timeout <= 0:
                raise asyncio.TimeoutError()
            
            # 3. Read Response Line
            line = await asyncio.wait_for(reader.readline(), timeout=remaining_timeout)
            
            first_byte_end_time = time.monotonic()
            first_byte_ms = (first_byte_end_time - connect_end_time) * 1000.0
            total_ms = (first_byte_end_time - start_time) * 1000.0
            
            status_code = None
            protocol = None
            if line:
                parts = line.decode("utf-8", errors="ignore").strip().split(" ", 2)
                if len(parts) >= 2:
                    protocol = parts[0]
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass
            
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
                    "connect_tls_ms": connect_ms,
                    "first_byte_ms": first_byte_ms,
                    "total_ms": total_ms
                },
                details={
                    "status_code": status_code,
                    "protocol": protocol,
                },
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
        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            
            try:
                if writer is not None:
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
                error=f"HTTP request failed: {str(e)}",
            )

import asyncio
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from connscope.core import Probe, ProbeResult, ProbeStatus, Target
from ._utils import parse_connect_ip

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

        pinned_ip, ip_err = parse_connect_ip(config)
        if ip_err:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=0.0,
                error=ip_err,
            )

        if pinned_ip is not None and (config or {}).get("verify", True) is False:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=0.0,
                error="Disabling TLS verification is not allowed when connect_ip is pinned",
            )

        use_tls = (config or {}).get("use_tls", True)
        port = target.port if target.port is not None else (443 if use_tls else 80)
        connect_host = pinned_ip if pinned_ip is not None else target.host

        writer = None
        try:
            if use_tls:
                ssl_context = ssl.create_default_context()
                if (config or {}).get("verify", True) is False:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                server_hostname = (
                    target.host[1:-1]
                    if (target.host.startswith("[") and target.host.endswith("]"))
                    else target.host
                )
            else:
                ssl_context = None
                server_hostname = None

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    connect_host,
                    port,
                    ssl=ssl_context,
                    server_hostname=server_hostname,
                ),
                timeout=timeout_s,
            )

            connect_end_time = time.monotonic()
            connect_ms = (connect_end_time - start_time) * 1000.0

            path = (config or {}).get("path", "/")
            method = (config or {}).get("method", "GET")

            host_header = f"[{target.host}]" if ":" in target.host and not target.host.startswith("[") else target.host
            default_port = 443 if use_tls else 80
            if port != default_port:
                host_header = f"{host_header}:{port}"

            request = f"{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode("utf-8"))
            await writer.drain()

            remaining_timeout = timeout_s - (time.monotonic() - start_time)
            if remaining_timeout <= 0:
                raise asyncio.TimeoutError()

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

            details: dict[str, Any] = {
                "status_code": status_code,
                "protocol": protocol,
            }
            if pinned_ip is not None:
                details["connect_ip"] = pinned_ip

            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=started_at,
                duration_ms=total_ms,
                metrics={
                    "connect_tls_ms": connect_ms,
                    "first_byte_ms": first_byte_ms,
                    "total_ms": total_ms,
                },
                details=details,
            )

        except asyncio.TimeoutError:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            details = {}
            if pinned_ip is not None:
                details["connect_ip"] = pinned_ip
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.TIMEOUT,
                started_at=started_at,
                duration_ms=duration_ms,
                details=details,
                error=f"Operation timed out after {timeout_s}s",
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            details = {}
            if pinned_ip is not None:
                details["connect_ip"] = pinned_ip
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                details=details,
                error=f"HTTP request failed: {str(e)}",
            )
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

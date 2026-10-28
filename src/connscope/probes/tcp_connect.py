import asyncio
import time
from datetime import datetime, timezone
from typing import Any

from connscope.core import Probe, ProbeResult, ProbeStatus, Target
from ._utils import parse_connect_ip

class TcpConnectProbe(Probe):
    name = "tcp_connect"

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

        if target.port is None:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=0.0,
                error="Target port is required for TCP connect probe",
            )

        connect_host = pinned_ip if pinned_ip is not None else target.host

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_host, target.port),
                timeout=timeout_s,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            duration_ms = (time.monotonic() - start_time) * 1000.0

            details = {}
            if pinned_ip is not None:
                details["connect_ip"] = pinned_ip

            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=started_at,
                duration_ms=duration_ms,
                metrics={"connect_ms": duration_ms},
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
                error=f"Connection timed out after {timeout_s}s",
            )
        except OSError as e:
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
                error=str(e),
            )

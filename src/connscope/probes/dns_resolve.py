import asyncio
import socket
import time
from datetime import datetime, timezone
from typing import Any

from connscope.core import Probe, ProbeResult, ProbeStatus, Target

class DnsResolveProbe(Probe):
    name = "dns_resolve"

    async def run(
        self,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ProbeResult:
        timeout_s = float((config or {}).get("timeout_s", 10.0))
        started_at = datetime.now(timezone.utc)
        start_time = time.monotonic()
        
        loop = asyncio.get_running_loop()
        
        try:
            # We don't specify port since we just want to resolve the host
            # 0 is the dummy port.
            addrinfo = await asyncio.wait_for(
                loop.getaddrinfo(target.host, 0, type=socket.SOCK_STREAM),
                timeout=timeout_s
            )
            
            duration_ms = (time.monotonic() - start_time) * 1000.0
            
            # Extract unique IPs, preserving order of first appearance
            addresses = []
            families = set()
            
            for info in addrinfo:
                family, _, _, _, sockaddr = info
                ip = sockaddr[0]
                if ip not in addresses:
                    addresses.append(ip)
                if family == socket.AF_INET:
                    families.add("ipv4")
                elif family == socket.AF_INET6:
                    families.add("ipv6")
            
            # Determine overall family
            if "ipv4" in families and "ipv6" in families:
                family_str = "both"
            elif "ipv6" in families:
                family_str = "ipv6"
            elif "ipv4" in families:
                family_str = "ipv4"
            else:
                family_str = "unknown"
                
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=started_at,
                duration_ms=duration_ms,
                metrics={"resolve_ms": duration_ms},
                details={
                    "addresses": addresses,
                    "family": family_str
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
                error=f"DNS resolution timed out after {timeout_s}s",
            )
        except socket.gaierror as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                error=f"DNS resolution failed: {e.strerror}",
            )
        except OSError as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                error=str(e),
            )

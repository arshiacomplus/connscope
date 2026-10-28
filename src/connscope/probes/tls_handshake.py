import asyncio
import ipaddress
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from connscope.core import Probe, ProbeResult, ProbeStatus, Target
from ._utils import (
    normalize_ascii_domain,
    parse_connect_ip,
    validate_sni,
    verify_certificate_hostname,
)

class TlsHandshakeProbe(Probe):
    name = "tls_handshake"

    async def run(
        self,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ProbeResult:
        cfg = config or {}
        timeout_s = float(cfg.get("timeout_s", 10.0))
        started_at = datetime.now(timezone.utc)
        start_time = time.monotonic()

        clean_target_host = (
            target.host[1:-1]
            if (target.host.startswith("[") and target.host.endswith("]"))
            else target.host
        )
        try:
            ipaddress.ip_address(clean_target_host)
            target_is_ip = True
        except ValueError:
            target_is_ip = False

        if not target_is_ip:
            norm_target, target_err = normalize_ascii_domain(clean_target_host)
            if norm_target is None:
                return ProbeResult(
                    probe=self.name,
                    target=target,
                    status=ProbeStatus.FAILED,
                    started_at=started_at,
                    duration_ms=0.0,
                    details={"handshake_completed": False},
                    error=target_err,
                )

        no_sni = cfg.get("no_sni", False)
        if not isinstance(no_sni, bool):
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=0.0,
                details={"handshake_completed": False},
                error="no_sni must be a boolean",
            )

        custom_sni = cfg.get("sni")
        if custom_sni is not None and not isinstance(custom_sni, str):
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=0.0,
                details={"handshake_completed": False},
                error="sni must be a string",
            )

        if no_sni and custom_sni is not None:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=0.0,
                details={"handshake_completed": False},
                error="Cannot specify both sni and no_sni",
            )

        if custom_sni is not None:
            try:
                validate_sni(custom_sni)
            except ValueError as exc:
                return ProbeResult(
                    probe=self.name,
                    target=target,
                    status=ProbeStatus.FAILED,
                    started_at=started_at,
                    duration_ms=0.0,
                    details={"handshake_completed": False},
                    error=f"Invalid SNI: {exc}",
                )

        if no_sni:
            server_hostname: str | None = None
        elif custom_sni is not None:
            server_hostname = custom_sni
        else:
            server_hostname = clean_target_host

        pinned_ip, ip_err = parse_connect_ip(config)
        if ip_err:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=0.0,
                details={"handshake_completed": False},
                error=ip_err,
            )

        verify = cfg.get("verify", True)
        if pinned_ip is not None and verify is False:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=0.0,
                details={"handshake_completed": False},
                error="Disabling TLS verification is not allowed when connect_ip is pinned",
            )

        port = target.port if target.port is not None else 443
        connect_host = pinned_ip if pinned_ip is not None else target.host

        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_host, port),
                timeout=timeout_s,
            )

            connect_end_time = time.monotonic()
            connect_ms = (connect_end_time - start_time) * 1000.0

            ssl_context = ssl.create_default_context()

            if verify is False:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            else:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_REQUIRED

            remaining_timeout = timeout_s - (connect_end_time - start_time)
            if remaining_timeout <= 0:
                raise asyncio.TimeoutError()

            await asyncio.wait_for(
                writer.start_tls(ssl_context, server_hostname=server_hostname),
                timeout=remaining_timeout,
            )

            handshake_end_time = time.monotonic()
            handshake_ms = (handshake_end_time - connect_end_time) * 1000.0
            total_ms = (handshake_end_time - start_time) * 1000.0

            ssl_object = writer.get_extra_info("ssl_object")
            details: dict[str, Any] = {
                "handshake_completed": True,
                "sni": server_hostname,
            }
            if pinned_ip is not None:
                details["connect_ip"] = pinned_ip

            metrics = {
                "connect_ms": connect_ms,
                "handshake_ms": handshake_ms,
                "total_ms": total_ms,
            }

            if ssl_object:
                details["tls_version"] = ssl_object.version()
                details["cipher"] = ssl_object.cipher()[0] if ssl_object.cipher() else None
                cert = ssl_object.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    details["cert_subject"] = subject.get("commonName")

                    if verify is True:
                        matched, mismatch_err = verify_certificate_hostname(cert, target.host)
                        if not matched:
                            details["hostname_verified"] = False
                            return ProbeResult(
                                probe=self.name,
                                target=target,
                                status=ProbeStatus.FAILED,
                                started_at=started_at,
                                duration_ms=total_ms,
                                metrics=metrics,
                                details=details,
                                error=f"Certificate hostname mismatch: {mismatch_err}",
                            )
                        details["hostname_verified"] = True
                elif verify is True and ssl_context.verify_mode == ssl.CERT_REQUIRED:
                    details["hostname_verified"] = False
                    return ProbeResult(
                        probe=self.name,
                        target=target,
                        status=ProbeStatus.FAILED,
                        started_at=started_at,
                        duration_ms=total_ms,
                        metrics=metrics,
                        details=details,
                        error="No peer certificate presented",
                    )

            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=started_at,
                duration_ms=total_ms,
                metrics=metrics,
                details=details,
            )

        except asyncio.TimeoutError:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            details = {"handshake_completed": False}
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
        except ssl.SSLCertVerificationError as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            details = {"handshake_completed": False}
            if pinned_ip is not None:
                details["connect_ip"] = pinned_ip
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                details=details,
                error=f"TLS certificate verification failed: {str(e)}",
            )
        except ssl.SSLError as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            details = {"handshake_completed": False}
            if pinned_ip is not None:
                details["connect_ip"] = pinned_ip
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                details=details,
                error=f"TLS handshake failed: {str(e)}",
            )
        except OSError as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            details = {"handshake_completed": False}
            if pinned_ip is not None:
                details["connect_ip"] = pinned_ip
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                details=details,
                error=f"TCP connection failed: {str(e)}",
            )
        except asyncio.CancelledError:
            raise
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

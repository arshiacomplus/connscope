import asyncio
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import signal
import socket
import ssl
import time
from typing import Any, NamedTuple, Sequence
import urllib.parse

from .security import DEFAULT_OUTPUT_LIMIT_BYTES

def find_free_loopback_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(s.getsockname()[1])

def scrub_sensitive_text(text: str, secrets: Sequence[str]) -> str:
    if not text or not secrets:
        return text
    clean = text
    for secret in secrets:
        if secret and len(secret) >= 3:
            clean = clean.replace(secret, "[REDACTED]")
    return clean

async def read_bounded_stream(
    stream: asyncio.StreamReader | None,
    limit: int = DEFAULT_OUTPUT_LIMIT_BYTES,
) -> bytes:
    if stream is None:
        return b""
    buffer = bytearray()
    while True:
        try:
            chunk = await stream.read(4096)
            if not chunk:
                break
            if len(buffer) < limit:
                remaining = limit - len(buffer)
                buffer.extend(chunk[:remaining])
        except Exception:
            break
    return bytes(buffer)

async def terminate_process_tree(
    proc: asyncio.subprocess.Process,
    timeout: float = 2.0,
) -> None:
    if proc.returncode is not None:
        return

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass

    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except Exception:
            pass

async def wait_for_proxy_ready(
    host: str,
    port: int,
    proc: asyncio.subprocess.Process,
    timeout_s: float = 3.0,
) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            return False
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=0.2,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.05)
    return False

class TunnelVerificationResult(NamedTuple):

    tunnel_established: bool
    data_transfer_completed: bool
    handshake_ms: float
    data_transfer_ms: float
    http_status: int | None = None
    error_message: str | None = None
    tls_verified: bool | None = None
    tls_handshake_ms: float = 0.0
    tls_handshake_completed: bool | None = None

async def verify_tunnel_and_data_transfer(
    proxy_host: str,
    proxy_port: int,
    test_url: str,
    timeout_s: float,
    verify_cert: bool = True,
    ssl_context: ssl.SSLContext | None = None,
) -> TunnelVerificationResult:
    t_start = time.monotonic()
    parsed = urllib.parse.urlsplit(test_url)
    dest_host = parsed.hostname or "cp.cloudflare.com"
    is_https = parsed.scheme.lower() == "https"
    dest_port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port),
            timeout=timeout_s,
        )

        writer.write(b"\x05\x01\x00")
        await writer.drain()

        rem_auth = max(0.1, timeout_s - (time.monotonic() - t_start))
        auth_reply = await asyncio.wait_for(reader.readexactly(2), timeout=rem_auth)
        if auth_reply != b"\x05\x00":
            return TunnelVerificationResult(
                tunnel_established=False,
                data_transfer_completed=False,
                handshake_ms=0.0,
                data_transfer_ms=0.0,
                http_status=None,
                error_message=f"SOCKS5 authentication failed: {auth_reply.hex()}",
                tls_verified=False if is_https else None,
                tls_handshake_ms=0.0,
                tls_handshake_completed=False if is_https else None,
            )

        t_tunnel_start = time.monotonic()
        try:
            ip = ipaddress.ip_address(dest_host)
            atyp = (b"\x01" + ip.packed) if isinstance(ip, ipaddress.IPv4Address) else (b"\x04" + ip.packed)
        except ValueError:
            h_bytes = dest_host.encode("ascii")
            atyp = b"\x03" + bytes([len(h_bytes)]) + h_bytes

        writer.write(b"\x05\x01\x00" + atyp + dest_port.to_bytes(2, "big"))
        await writer.drain()

        rem_conn = max(0.1, timeout_s - (time.monotonic() - t_start))
        reply_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=rem_conn)
        if reply_hdr[3] == 0x01:
            await asyncio.wait_for(reader.readexactly(6), timeout=rem_conn)
        elif reply_hdr[3] == 0x03:
            lb = await asyncio.wait_for(reader.readexactly(1), timeout=rem_conn)
            await asyncio.wait_for(reader.readexactly(lb[0] + 2), timeout=rem_conn)
        elif reply_hdr[3] == 0x04:
            await asyncio.wait_for(reader.readexactly(18), timeout=rem_conn)

        handshake_ms = (time.monotonic() - t_tunnel_start) * 1000.0

        if reply_hdr[1] != 0x00:
            err_codes = {
                1: "General SOCKS server failure",
                2: "Connection not allowed by ruleset",
                3: "Network unreachable",
                4: "Host unreachable",
                5: "Connection refused",
                6: "TTL expired",
                7: "Command not supported",
                8: "Address type not supported",
            }
            desc = err_codes.get(reply_hdr[1], f"SOCKS5 error code {reply_hdr[1]}")
            return TunnelVerificationResult(
                tunnel_established=False,
                data_transfer_completed=False,
                handshake_ms=handshake_ms,
                data_transfer_ms=0.0,
                http_status=None,
                error_message=f"Tunnel establishment failed: {desc}",
                tls_verified=False if is_https else None,
                tls_handshake_ms=0.0,
                tls_handshake_completed=False if is_https else None,
            )

        tunnel_established = True

        tls_verified: bool | None = None
        tls_handshake_ms = 0.0

        if is_https:
            t_tls_start = time.monotonic()
            if ssl_context is None:
                ctx = ssl.create_default_context()
                if not verify_cert:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
            else:
                ctx = ssl_context

            rem_tls = max(0.1, timeout_s - (time.monotonic() - t_start))
            try:
                await asyncio.wait_for(
                    writer.start_tls(ctx, server_hostname=dest_host),
                    timeout=rem_tls,
                )
                tls_handshake_ms = (time.monotonic() - t_tls_start) * 1000.0
                tls_verified = bool(verify_cert and ctx.verify_mode != ssl.CERT_NONE)
            except ssl.SSLCertVerificationError as exc:
                tls_handshake_ms = (time.monotonic() - t_tls_start) * 1000.0
                return TunnelVerificationResult(
                    tunnel_established=True,
                    data_transfer_completed=False,
                    handshake_ms=handshake_ms,
                    data_transfer_ms=0.0,
                    http_status=None,
                    error_message=f"TLS certificate verification failed: {exc}",
                    tls_verified=False,
                    tls_handshake_ms=tls_handshake_ms,
                    tls_handshake_completed=False,
                )
            except (ssl.SSLError, OSError) as exc:
                tls_handshake_ms = (time.monotonic() - t_tls_start) * 1000.0
                return TunnelVerificationResult(
                    tunnel_established=True,
                    data_transfer_completed=False,
                    handshake_ms=handshake_ms,
                    data_transfer_ms=0.0,
                    http_status=None,
                    error_message=f"TLS handshake failed: {exc}",
                    tls_verified=False,
                    tls_handshake_ms=tls_handshake_ms,
                    tls_handshake_completed=False,
                )

        t_data_start = time.monotonic()
        http_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"User-Agent: ConnScope/0.1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(http_req)
        await writer.drain()

        rem_data = max(0.1, timeout_s - (time.monotonic() - t_start))
        response_line = await asyncio.wait_for(reader.readline(), timeout=rem_data)
        data_transfer_ms = (time.monotonic() - t_data_start) * 1000.0

        if not response_line:
            return TunnelVerificationResult(
                tunnel_established=True,
                data_transfer_completed=False,
                handshake_ms=handshake_ms,
                data_transfer_ms=data_transfer_ms,
                http_status=None,
                error_message="Data transfer failed: Empty response from destination",
                tls_verified=tls_verified,
                tls_handshake_ms=tls_handshake_ms,
                tls_handshake_completed=True if is_https else None,
            )

        parts = response_line.decode("iso-8859-1", errors="replace").strip().split(None, 2)
        if len(parts) >= 2 and parts[1].isdigit():
            http_status = int(parts[1])
        else:
            return TunnelVerificationResult(
                tunnel_established=True,
                data_transfer_completed=False,
                handshake_ms=handshake_ms,
                data_transfer_ms=data_transfer_ms,
                http_status=None,
                error_message=f"Data transfer failed: Malformed HTTP status '{response_line.decode('iso-8859-1', errors='replace').strip()}'",
                tls_verified=tls_verified,
                tls_handshake_ms=tls_handshake_ms,
                tls_handshake_completed=True if is_https else None,
            )

        if 200 <= http_status < 400:
            return TunnelVerificationResult(
                tunnel_established=True,
                data_transfer_completed=True,
                handshake_ms=handshake_ms,
                data_transfer_ms=data_transfer_ms,
                http_status=http_status,
                error_message=None,
                tls_verified=tls_verified,
                tls_handshake_ms=tls_handshake_ms,
                tls_handshake_completed=True if is_https else None,
            )
        else:
            return TunnelVerificationResult(
                tunnel_established=True,
                data_transfer_completed=False,
                handshake_ms=handshake_ms,
                data_transfer_ms=data_transfer_ms,
                http_status=http_status,
                error_message=f"Data transfer failed with HTTP {http_status}",
                tls_verified=tls_verified,
                tls_handshake_ms=tls_handshake_ms,
                tls_handshake_completed=True if is_https else None,
            )

    except asyncio.TimeoutError:
        return TunnelVerificationResult(
            tunnel_established=False,
            data_transfer_completed=False,
            handshake_ms=0.0,
            data_transfer_ms=0.0,
            http_status=None,
            error_message="Operation timed out during tunnel verification or data transfer",
            tls_verified=False if is_https else None,
            tls_handshake_ms=0.0,
            tls_handshake_completed=False if is_https else None,
        )
    except (OSError, asyncio.IncompleteReadError) as exc:
        return TunnelVerificationResult(
            tunnel_established=False,
            data_transfer_completed=False,
            handshake_ms=0.0,
            data_transfer_ms=0.0,
            http_status=None,
            error_message=f"Network error during tunnel verification: {exc}",
            tls_verified=False if is_https else None,
            tls_handshake_ms=0.0,
            tls_handshake_completed=False if is_https else None,
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Iterator

ALLOWED_EXECUTABLES: frozenset[str] = frozenset({
    "xray",
    "sing-box",
    "v2ray",
    "exclave",
    "wg",
    "awg",
    "wireguard",
    "openvpn",
    "ssh",
    "dnstt-client",
    "dnstt-server",
})

SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset({
    "auth",
    "authorization",
    "cookie",
    "credentials",
    "key",
    "password",
    "passwd",
    "pbk",
    "preshared_key",
    "privkey",
    "private_key",
    "psk",
    "pubkey",
    "public_key",
    "pwd",
    "secret",
    "secret_key",
    "short_id",
    "shortid",
    "token",
    "uuid",
})

DEFAULT_OUTPUT_LIMIT_BYTES: int = 64 * 1024
DEFAULT_EXECUTION_TIMEOUT_S: float = 30.0

def _get_default_lookup_paths() -> tuple[str, ...]:
    paths = [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]
    user_proxy_dirs = [
        str(Path.home() / "ACP-Portable/tools/proxy/bin"),
        str(Path.home() / ".local/share/v2rayN/bin/sing_box"),
    ]
    for d in user_proxy_dirs:
        if os.path.isdir(d) and d not in paths:
            paths.append(d)
    return tuple(paths)

DEFAULT_LOOKUP_PATHS: tuple[str, ...] = _get_default_lookup_paths()

def redact_sensitive_data(val: Any) -> Any:
    if isinstance(val, dict):
        redacted: dict[str, Any] = {}
        for k, v in val.items():
            if not isinstance(k, str):
                continue
            k_lower = k.lower().replace("-", "_")
            if k_lower in SENSITIVE_FIELD_NAMES or any(
                secret_word in k_lower
                for secret_word in ("password", "private_key", "secret", "preshared_key")
            ):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_data(v)
        return redacted

    if isinstance(val, list):
        return [redact_sensitive_data(item) for item in val]

    if isinstance(val, tuple):
        return tuple(redact_sensitive_data(item) for item in val)

    return val

def resolve_safe_executable(
    binary_name: str,
    lookup_paths: tuple[str, ...] | None = None,
) -> str | None:
    if not isinstance(binary_name, str) or not binary_name.strip():
        raise ValueError("binary_name must be a non-empty string")

    clean_name = binary_name.strip()
    if "/" in clean_name or "\\" in clean_name:
        raise ValueError(f"Path separators are not allowed in binary_name '{binary_name}'")

    if clean_name not in ALLOWED_EXECUTABLES:
        raise ValueError(f"Executable '{clean_name}' is not permitted by allowlist")

    actual_paths = lookup_paths if lookup_paths is not None else DEFAULT_LOOKUP_PATHS
    for directory in actual_paths:
        candidate = Path(directory) / clean_name
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate.resolve())
        except (OSError, PermissionError):
            continue

    return None

def validate_command_args(args: list[str]) -> list[str]:
    if not isinstance(args, list) or not args:
        raise ValueError("Command arguments must be a non-empty list of strings")

    for i, arg in enumerate(args):
        if not isinstance(arg, str):
            raise TypeError(f"Argument at index {i} must be a str, got {type(arg).__name__}")
        if not arg.strip() and i == 0:
            raise ValueError("Executable argument (index 0) must not be empty or whitespace")

    executable_arg = args[0].strip()
    binary_name = Path(executable_arg).name
    if binary_name not in ALLOWED_EXECUTABLES:
        raise ValueError(f"Command executable '{binary_name}' is not in the allowlist")

    return list(args)

@contextmanager
def safe_temporary_workspace(prefix: str = "connscope_engine_") -> Iterator[Path]:
    tmp_dir = tempfile.mkdtemp(prefix=prefix)
    try:
        os.chmod(tmp_dir, 0o700)
        yield Path(tmp_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

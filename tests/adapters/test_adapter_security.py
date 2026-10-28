import os
from pathlib import Path
import stat
import pytest

from connscope.adapters.security import (
    ALLOWED_EXECUTABLES,
    DEFAULT_EXECUTION_TIMEOUT_S,
    DEFAULT_OUTPUT_LIMIT_BYTES,
    redact_sensitive_data,
    resolve_safe_executable,
    safe_temporary_workspace,
    validate_command_args,
)

def test_redact_sensitive_data_keys():
    config = {
        "host": "example.com",
        "port": 443,
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "password": "super-secret-password",
        "private_key": "private_key_content",
        "nested": {
            "token": "bearer-token-123",
            "short_id": "ab12cd34",
            "safe_param": "visible",
            "list_items": [
                {"psk": "preshared-key-xyz", "name": "item1"},
                "plain_string",
            ],
        },
    }

    redacted = redact_sensitive_data(config)

    assert redacted["host"] == "example.com"
    assert redacted["port"] == 443
    assert redacted["uuid"] == "[REDACTED]"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["private_key"] == "[REDACTED]"

    assert redacted["nested"]["token"] == "[REDACTED]"
    assert redacted["nested"]["short_id"] == "[REDACTED]"
    assert redacted["nested"]["safe_param"] == "visible"

    assert redacted["nested"]["list_items"][0]["psk"] == "[REDACTED]"
    assert redacted["nested"]["list_items"][0]["name"] == "item1"
    assert redacted["nested"]["list_items"][1] == "plain_string"

    assert config["password"] == "super-secret-password"

def test_redact_sensitive_data_case_insensitivity():
    data = {
        "PASSWORD": "123",
        "Private-Key": "abc",
        "My_Secret_Value": "xyz",
    }
    redacted = redact_sensitive_data(data)
    assert redacted["PASSWORD"] == "[REDACTED]"
    assert redacted["Private-Key"] == "[REDACTED]"
    assert redacted["My_Secret_Value"] == "[REDACTED]"

def test_resolve_safe_executable_allowlist():
    assert "xray" in ALLOWED_EXECUTABLES
    assert "sing-box" in ALLOWED_EXECUTABLES

    with pytest.raises(ValueError, match="Executable 'bash' is not permitted"):
        resolve_safe_executable("bash")

    with pytest.raises(ValueError, match="Executable 'curl' is not permitted"):
        resolve_safe_executable("curl")

    with pytest.raises(ValueError, match="Path separators are not allowed"):
        resolve_safe_executable("/usr/bin/xray")

    with pytest.raises(ValueError, match="Path separators are not allowed"):
        resolve_safe_executable("../bin/xray")

    with pytest.raises(ValueError, match="must be a non-empty string"):
        resolve_safe_executable("")

def test_resolve_safe_executable_discovery(tmp_path: Path):
    fake_bin = tmp_path / "xray"
    fake_bin.write_text("#!/bin/sh\necho xray\n")
    fake_bin.chmod(0o755)

    resolved = resolve_safe_executable("xray", lookup_paths=(str(tmp_path),))
    assert resolved is not None
    assert resolved == str(fake_bin.resolve())

    missing = resolve_safe_executable("xray", lookup_paths=("/nonexistent/path",))
    assert missing is None

def test_validate_command_args():
    valid_args = ["xray", "run", "-c", "config.json"]
    assert validate_command_args(valid_args) == valid_args

    valid_path_args = ["/usr/bin/xray", "version"]
    assert validate_command_args(valid_path_args) == valid_path_args

    with pytest.raises(ValueError, match="must be a non-empty list"):
        validate_command_args([])

    with pytest.raises(ValueError, match="must be a non-empty list"):
        validate_command_args(None)  # type: ignore

    with pytest.raises(TypeError, match="must be a str"):
        validate_command_args(["xray", 123])  # type: ignore

    with pytest.raises(ValueError, match="must not be empty or whitespace"):
        validate_command_args(["   ", "arg"])

    with pytest.raises(ValueError, match="is not in the allowlist"):
        validate_command_args(["sh", "-c", "echo hello"])

def test_safe_temporary_workspace():
    workspace_path = None
    with safe_temporary_workspace(prefix="test_scope_") as ws:
        assert ws.exists()
        assert ws.is_dir()
        workspace_path = ws

        mode = stat.S_IMODE(os.stat(ws).st_mode)
        assert mode == 0o700

        test_file = ws / "test.txt"
        test_file.write_text("temporary data")
        assert test_file.exists()

    assert workspace_path is not None
    assert not workspace_path.exists()

def test_safe_temporary_workspace_cleans_up_on_error():
    workspace_path = None
    with pytest.raises(RuntimeError, match="Simulated failure"):
        with safe_temporary_workspace() as ws:
            workspace_path = ws
            (ws / "dummy.json").write_text("{}")
            raise RuntimeError("Simulated failure")

    assert workspace_path is not None
    assert not workspace_path.exists()

def test_default_limits_constants():
    assert DEFAULT_OUTPUT_LIMIT_BYTES >= 32 * 1024
    assert DEFAULT_EXECUTION_TIMEOUT_S > 0

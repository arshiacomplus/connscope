
import pytest

from connscope.adapters import (
    ALLOWED_WIREGUARD_CONFIG_KEYS,
    generate_wireguard_client_config,
    redact_sensitive_data,
    validate_wireguard_config,
    validate_wireguard_key,
)
from connscope.core import Target

SAMPLE_TARGET = Target(host="198.51.100.1", port=51820)

CLIENT_PRIVKEY = "YAmZ1y5v+7vX+Z/Qf6s5k1y5v+7vX+Z/Qf6s5k1y5v8="
PEER_PUBKEY = "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk="
PEER_PUBKEY_STD = "8n5WzXghUgGfcEzTt+vGU5ZXAij+pc5rVni0dyJ0xhk="
PSK_KEY = "F/4b1v5y+7vX+Z/Qf6s5k1y5v+7vX+Z/Qf6s5k1y5v4="

def test_validate_wireguard_key_success():
    key = validate_wireguard_key(CLIENT_PRIVKEY, "client_private_key")
    assert key == CLIENT_PRIVKEY

    unpadded = CLIENT_PRIVKEY.rstrip("=")
    key2 = validate_wireguard_key(unpadded, "unpadded_key")
    assert key2 == unpadded

def test_validate_wireguard_key_invalid_length():
    short_key = "YAmZ1y5v+7vX+Z/Qf6s5k1w="
    with pytest.raises(ValueError, match="must decode to exactly 32 bytes"):
        validate_wireguard_key(short_key)

    long_key = "YAmZ1y5v+7vX+Z/Qf6s5k1y5v+7vX+Z/Qf6s5k1y5v812345"
    with pytest.raises(ValueError, match="must decode to exactly 32 bytes"):
        validate_wireguard_key(long_key)

def test_validate_wireguard_key_invalid_characters_or_type():
    with pytest.raises(TypeError, match="must be a string"):
        validate_wireguard_key(12345)

    with pytest.raises(ValueError, match="must not be empty"):
        validate_wireguard_key("   ")

    with pytest.raises(ValueError, match="Invalid base64 encoding"):
        validate_wireguard_key("!@#$%^&*()_+!@#$%^&*()_+!@#$%^&*()_+!@#$")

def test_validate_wireguard_config_valid_minimal():
    cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY_STD,
    }
    validated = validate_wireguard_config(cfg, target=SAMPLE_TARGET)

    assert validated["private_key"] == CLIENT_PRIVKEY
    assert validated["public_key"] == PEER_PUBKEY_STD
    assert validated["endpoint"] == "198.51.100.1:51820"
    assert validated["allowed_ips"] == "0.0.0.0/0, ::/0"
    assert validated["address"] == "10.0.0.2/32"
    assert validated["mtu"] == 1420
    assert validated["persistent_keepalive"] == 25
    assert "preshared_key" not in validated

def test_validate_wireguard_config_valid_full():
    cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY_STD,
        "preshared_key": PSK_KEY,
        "endpoint": "vpn.example.com:51820",
        "allowed_ips": "10.0.0.0/24, 192.168.1.0/24",
        "address": "10.0.0.5/24",
        "listen_port": 51820,
        "mtu": 1280,
        "persistent_keepalive": 15,
        "dns": "1.1.1.1, 8.8.8.8",
        "test_url": "https://cp.cloudflare.com/generate_204",
        "timeout_s": 5.0,
    }
    validated = validate_wireguard_config(cfg, target=SAMPLE_TARGET)

    assert validated["preshared_key"] == PSK_KEY
    assert validated["endpoint"] == "vpn.example.com:51820"
    assert validated["allowed_ips"] == "10.0.0.0/24, 192.168.1.0/24"
    assert validated["address"] == "10.0.0.5/24"
    assert validated["listen_port"] == 51820
    assert validated["mtu"] == 1280
    assert validated["persistent_keepalive"] == 15
    assert validated["dns"] == "1.1.1.1, 8.8.8.8"
    assert validated["test_url"] == "https://cp.cloudflare.com/generate_204"
    assert validated["timeout_s"] == 5.0

def test_validate_wireguard_config_missing_required_keys():
    with pytest.raises(ValueError, match="Missing required parameter 'private_key'"):
        validate_wireguard_config({"public_key": PEER_PUBKEY_STD}, target=SAMPLE_TARGET)

    with pytest.raises(ValueError, match="Missing required parameter 'public_key'"):
        validate_wireguard_config({"private_key": CLIENT_PRIVKEY}, target=SAMPLE_TARGET)

def test_validate_wireguard_config_rejection_of_amnezia_parameters():
    cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY_STD,
        "jc": 4,
    }
    with pytest.raises(ValueError, match="Unknown parameter 'jc'"):
        validate_wireguard_config(cfg, target=SAMPLE_TARGET)

    cfg2 = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY_STD,
        "jmin": 40,
    }
    with pytest.raises(ValueError, match="Unknown parameter 'jmin'"):
        validate_wireguard_config(cfg2, target=SAMPLE_TARGET)

def test_validate_wireguard_config_mtu_bounds():
    base_cfg = {"private_key": CLIENT_PRIVKEY, "public_key": PEER_PUBKEY_STD}

    res_low = validate_wireguard_config({**base_cfg, "mtu": 1280}, target=SAMPLE_TARGET)
    assert res_low["mtu"] == 1280

    res_high = validate_wireguard_config({**base_cfg, "mtu": 1500}, target=SAMPLE_TARGET)
    assert res_high["mtu"] == 1500

    with pytest.raises(ValueError, match="mtu must be between 1280 and 1500"):
        validate_wireguard_config({**base_cfg, "mtu": 1279}, target=SAMPLE_TARGET)

    with pytest.raises(ValueError, match="mtu must be between 1280 and 1500"):
        validate_wireguard_config({**base_cfg, "mtu": 1501}, target=SAMPLE_TARGET)

    with pytest.raises(TypeError, match="mtu must be an integer"):
        validate_wireguard_config({**base_cfg, "mtu": "1420"}, target=SAMPLE_TARGET)

def test_validate_wireguard_config_keepalive_bounds():
    base_cfg = {"private_key": CLIENT_PRIVKEY, "public_key": PEER_PUBKEY_STD}

    res_zero = validate_wireguard_config({**base_cfg, "persistent_keepalive": 0}, target=SAMPLE_TARGET)
    assert res_zero["persistent_keepalive"] == 0

    res_max = validate_wireguard_config({**base_cfg, "persistent_keepalive": 3600}, target=SAMPLE_TARGET)
    assert res_max["persistent_keepalive"] == 3600

    with pytest.raises(ValueError, match="persistent_keepalive must be between 0 and 3600"):
        validate_wireguard_config({**base_cfg, "persistent_keepalive": -1}, target=SAMPLE_TARGET)

    with pytest.raises(ValueError, match="persistent_keepalive must be between 0 and 3600"):
        validate_wireguard_config({**base_cfg, "persistent_keepalive": 3601}, target=SAMPLE_TARGET)

def test_validate_wireguard_config_invalid_cidrs():
    base_cfg = {"private_key": CLIENT_PRIVKEY, "public_key": PEER_PUBKEY_STD}

    with pytest.raises(ValueError, match="Invalid CIDR prefix in allowed_ips"):
        validate_wireguard_config({**base_cfg, "allowed_ips": "999.999.999.999/24"}, target=SAMPLE_TARGET)

    with pytest.raises(ValueError, match="Invalid interface address"):
        validate_wireguard_config({**base_cfg, "address": "not_an_ip"}, target=SAMPLE_TARGET)

def test_validate_wireguard_config_endpoint_and_ports():
    base_cfg = {"private_key": CLIENT_PRIVKEY, "public_key": PEER_PUBKEY_STD}

    with pytest.raises(ValueError, match="expected 'host:port'"):
        validate_wireguard_config({**base_cfg, "endpoint": "198.51.100.1"}, target=None)

    with pytest.raises(ValueError, match="Endpoint port 70000 must be between 1 and 65535"):
        validate_wireguard_config({**base_cfg, "endpoint": "198.51.100.1:70000"}, target=None)

    with pytest.raises(ValueError, match="listen_port must be between 1 and 65535"):
        validate_wireguard_config({**base_cfg, "listen_port": 0}, target=SAMPLE_TARGET)

def test_generate_wireguard_client_config():
    cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY_STD,
        "preshared_key": PSK_KEY,
        "endpoint": "198.51.100.1:51820",
        "allowed_ips": "0.0.0.0/0",
        "address": "10.0.0.2/32",
        "listen_port": 51820,
        "mtu": 1420,
        "persistent_keepalive": 25,
    }
    ini_text = generate_wireguard_client_config(cfg)

    assert "[Interface]" in ini_text
    assert f"PrivateKey = {CLIENT_PRIVKEY}" in ini_text
    assert "Address = 10.0.0.2/32" in ini_text
    assert "MTU = 1420" in ini_text
    assert "ListenPort = 51820" in ini_text

    assert "[Peer]" in ini_text
    assert f"PublicKey = {PEER_PUBKEY_STD}" in ini_text
    assert f"PresharedKey = {PSK_KEY}" in ini_text
    assert "Endpoint = 198.51.100.1:51820" in ini_text
    assert "AllowedIPs = 0.0.0.0/0" in ini_text
    assert "PersistentKeepalive = 25" in ini_text

def test_wireguard_secret_redaction():
    cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY_STD,
        "preshared_key": PSK_KEY,
        "endpoint": "198.51.100.1:51820",
        "mtu": 1420,
    }
    redacted = redact_sensitive_data(cfg)

    assert redacted["private_key"] == "[REDACTED]"
    assert redacted["preshared_key"] == "[REDACTED]"
    assert redacted["public_key"] == "[REDACTED]"
    assert redacted["endpoint"] == "198.51.100.1:51820"
    assert redacted["mtu"] == 1420

def test_generate_wireguard_wg_setconf_config_strictly_excludes_address_and_mtu():
    from connscope.adapters import generate_wireguard_wg_setconf_config

    cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY_STD,
        "preshared_key": PSK_KEY,
        "endpoint": "198.51.100.1:51820",
        "allowed_ips": "0.0.0.0/0",
        "address": "10.0.0.2/32",
        "listen_port": 51820,
        "mtu": 1420,
        "persistent_keepalive": 25,
        "dns": "1.1.1.1",
    }
    setconf_text = generate_wireguard_wg_setconf_config(cfg)

    assert "[Interface]" in setconf_text
    assert f"PrivateKey = {CLIENT_PRIVKEY}" in setconf_text
    assert "ListenPort = 51820" in setconf_text

    assert "[Peer]" in setconf_text
    assert f"PublicKey = {PEER_PUBKEY_STD}" in setconf_text
    assert f"PresharedKey = {PSK_KEY}" in setconf_text
    assert "Endpoint = 198.51.100.1:51820" in setconf_text
    assert "AllowedIPs = 0.0.0.0/0" in setconf_text
    assert "PersistentKeepalive = 25" in setconf_text

    assert "Address =" not in setconf_text
    assert "MTU =" not in setconf_text
    assert "DNS =" not in setconf_text

def test_rejection_of_wg_quick_hooks_and_arbitrary_commands():
    base_cfg = {"private_key": CLIENT_PRIVKEY, "public_key": PEER_PUBKEY_STD}

    for hook in ("PreUp", "pre_up", "PostUp", "post_up", "PreDown", "pre_down", "PostDown", "post_down"):
        with pytest.raises(ValueError, match=f"Unknown parameter '{hook}'"):
            validate_wireguard_config({**base_cfg, hook: "touch /tmp/evil"}, target=SAMPLE_TARGET)

    for key in ("Table", "table", "SaveConfig", "save_config"):
        with pytest.raises(ValueError, match=f"Unknown parameter '{key}'"):
            validate_wireguard_config({**base_cfg, key: "off"}, target=SAMPLE_TARGET)

def test_wireguard_adapter_generate_config_file_uses_wg_setconf_format(tmp_path):
    from connscope.adapters import WireGuardStandardAdapter

    adapter = WireGuardStandardAdapter()
    cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY_STD,
        "address": "10.0.0.2/32",
        "mtu": 1380,
    }
    cfg_file = adapter.generate_config_file(cfg, SAMPLE_TARGET, tmp_path)

    assert cfg_file.is_file()
    content = cfg_file.read_text(encoding="utf-8")

    file_mode = cfg_file.stat().st_mode & 0o777
    assert file_mode == 0o600

    assert f"PrivateKey = {CLIENT_PRIVKEY}" in content
    assert f"PublicKey = {PEER_PUBKEY_STD}" in content
    assert "Address =" not in content
    assert "MTU =" not in content

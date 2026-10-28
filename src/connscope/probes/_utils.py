import codecs
import ipaddress
import re
import unicodedata
from typing import Any

_DNS_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

def validate_a_label(label: str) -> tuple[bool, str | None]:
    if not isinstance(label, str):
        return False, "A-label must be a string"
    if not label.lower().startswith("xn--"):
        return True, None

    payload = label[4:]
    if not payload:
        return False, f"A-label '{label}' has empty Punycode payload"

    try:
        decoded = codecs.decode(payload.encode("ascii"), "punycode")
    except (UnicodeDecodeError, UnicodeError, ValueError) as exc:
        return False, f"A-label '{label}' contains malformed Punycode: {exc}"
    except Exception as exc:
        return False, f"A-label '{label}' failed Punycode decoding: {exc}"

    if not any(ord(c) > 127 for c in decoded):
        return False, f"A-label '{label}' decodes to all-ASCII string"

    if any(0xD800 <= ord(c) <= 0xDFFF or unicodedata.category(c) == "Cs" for c in decoded):
        return False, f"A-label '{label}' decodes to surrogate code points"
    if any(unicodedata.category(c) == "Cc" for c in decoded):
        return False, f"A-label '{label}' decodes to control characters"
    if any(c.isspace() or unicodedata.category(c).startswith("Z") for c in decoded):
        return False, f"A-label '{label}' decodes to whitespace characters"

    if not unicodedata.is_normalized("NFC", decoded):
        return False, f"A-label '{label}' decodes to non-NFC normalized Unicode"

    try:
        reencoded = codecs.encode(decoded, "punycode").decode("ascii")
    except Exception as exc:
        return False, f"A-label '{label}' failed Punycode re-encoding: {exc}"

    if reencoded.lower() != payload.lower():
        return False, f"A-label '{label}' fails Punycode round-trip encoding"

    return True, None

def validate_sni(sni: Any) -> str:
    if not isinstance(sni, str):
        raise ValueError("SNI hostname must be a string")
    if not sni or len(sni) > 253:
        raise ValueError("SNI hostname must be between 1 and 253 characters")
    if any(ord(c) > 127 for c in sni):
        raise ValueError("Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in sni):
        raise ValueError("SNI hostname contains whitespace or control characters")
    clean = sni.strip("[]")
    try:
        ipaddress.ip_address(clean)
        raise ValueError("SNI hostname must not be an IP address literal")
    except ValueError as exc:
        if "must not be an IP address literal" in str(exc):
            raise
    labels = sni.split(".")
    for label in labels:
        if not label:
            raise ValueError("SNI hostname cannot have empty labels")
        if len(label) > 63:
            raise ValueError("SNI hostname labels cannot exceed 63 characters")
        if label.lower().startswith("xn--"):
            ok, err = validate_a_label(label)
            if not ok:
                raise ValueError(err)
        if not _DNS_LABEL_REGEX.match(label):
            raise ValueError(f"Invalid characters in SNI label '{label}'")
    return sni

def normalize_ascii_domain(d: str, allow_wildcard: bool = False) -> tuple[str | None, str | None]:
    if not isinstance(d, str):
        return None, "Hostname must be a string"
    if not d:
        return None, "Hostname cannot be empty"
    if any(ord(c) > 127 for c in d):
        return None, "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required"
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in d):
        return None, "Hostname contains whitespace or control characters"
    d_clean = d.rstrip(".")
    if not d_clean:
        return None, "Hostname cannot be empty"
    if len(d_clean) > 253:
        return None, "Hostname exceeds maximum length of 253 characters"
    labels = d_clean.split(".")
    for i, label in enumerate(labels):
        if allow_wildcard and i == 0 and label == "*":
            continue
        if not label:
            return None, "Hostname cannot contain empty labels"
        if len(label) > 63:
            return None, "Hostname label exceeds 63 characters"
        if label.lower().startswith("xn--"):
            ok, err = validate_a_label(label)
            if not ok:
                return None, err
        if not _DNS_LABEL_REGEX.match(label):
            return None, f"Invalid characters in DNS label '{label}'"
    return ".".join(labels).lower(), None

def to_ascii_domain(d: str) -> str | None:
    norm, _ = normalize_ascii_domain(d, allow_wildcard=True)
    return norm

def _match_dns_pattern(pattern: str, normalized_hostname: str) -> bool:
    if not isinstance(pattern, str) or not isinstance(normalized_hostname, str):
        return False

    norm_pattern, pat_err = normalize_ascii_domain(pattern, allow_wildcard=True)
    if norm_pattern is None:
        return False

    if norm_pattern == normalized_hostname:
        return True

    if norm_pattern.count("*") == 1 and norm_pattern.startswith("*."):
        remainder = norm_pattern[2:]
        if "." not in remainder or remainder.startswith(".") or remainder.endswith("."):
            return False
        host_leftmost, sep, host_remainder = normalized_hostname.partition(".")
        if not sep or not host_leftmost:
            return False
        return host_remainder == remainder

    return False

def verify_certificate_hostname(cert: dict[str, Any], expected_hostname: str) -> tuple[bool, str | None]:
    norm_host = (
        expected_hostname[1:-1]
        if expected_hostname.startswith("[") and expected_hostname.endswith("]")
        else expected_hostname
    )
    try:
        expected_ip = ipaddress.ip_address(norm_host)
        is_ip = True
    except ValueError:
        expected_ip = None
        is_ip = False

    sans = cert.get("subjectAltName", ())
    if not isinstance(sans, (tuple, list)):
        sans = ()

    if is_ip:
        ip_sans: list[str] = []
        for entry in sans:
            if isinstance(entry, (tuple, list)) and len(entry) >= 2 and entry[0] == "IP Address":
                v = entry[1]
                if isinstance(v, str):
                    clean_v = v.rstrip()
                    ip_sans.append(clean_v)
                    try:
                        if ipaddress.ip_address(clean_v) == expected_ip:
                            return True, None
                    except ValueError:
                        pass
        san_str = ", ".join(repr(x) for x in ip_sans) if ip_sans else "none"
        return False, f"certificate does not match IP '{norm_host}' (IP SANs: {san_str})"

    clean_host, err = normalize_ascii_domain(norm_host, allow_wildcard=False)
    if clean_host is None:
        return False, err

    dns_sans: list[str] = []
    for entry in sans:
        if isinstance(entry, (tuple, list)) and len(entry) >= 2 and entry[0] == "DNS":
            v = entry[1]
            if isinstance(v, str):
                dns_sans.append(v)
                if _match_dns_pattern(v, clean_host):
                    return True, None

    san_str = ", ".join(repr(x) for x in dns_sans) if dns_sans else "none"
    return False, f"certificate does not match hostname '{clean_host}' (DNS SANs: {san_str})"

def parse_connect_ip(config: dict[str, Any] | None) -> tuple[str | None, str | None]:
    if not config or "connect_ip" not in config:
        return None, None

    raw = config["connect_ip"]
    if not isinstance(raw, str) or not raw.strip():
        return None, "Invalid connect_ip: must be a non-empty IP literal string"

    s = raw.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]

    try:
        ip_obj = ipaddress.ip_address(s)
    except ValueError:
        return None, f"Invalid connect_ip '{raw}': not a valid IPv4 or IPv6 literal"

    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    return str(ip_obj), None


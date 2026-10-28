import argparse
from pathlib import Path
import re
from urllib.parse import urlparse
import pytest
from connscope.cli.main import build_parser

def _get_project_root() -> Path:
    return Path(__file__).resolve().parent.parent

def _get_parser_options(parser: argparse.ArgumentParser) -> set[str]:
    opts: set[str] = set()
    for act in parser._actions:
        for opt in act.option_strings:
            opts.add(opt)
    return opts

def _build_command_option_tree(parser: argparse.ArgumentParser, prefix: str = "") -> dict[str, set[str]]:
    tree: dict[str, set[str]] = {prefix: _get_parser_options(parser)}
    for act in parser._actions:
        if isinstance(act, argparse._SubParsersAction):
            for sub_name, sub_p in act.choices.items():
                cmd_path = f"{prefix} {sub_name}".strip()
                tree.update(_build_command_option_tree(sub_p, cmd_path))
    return tree

def test_markdown_links_resolve() -> None:
    root = _get_project_root()
    docs_dir = root / "docs"
    md_files = list(docs_dir.rglob("*.md")) + [root / "README.md"]
    link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

    broken_links: list[str] = []
    for md_file in md_files:
        content = md_file.read_text(encoding="utf-8")
        for text, url in link_pattern.findall(content):
            url_str = url.strip()
            if url_str.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if url_str.startswith("file://"):
                parsed = urlparse(url_str)
                target = Path(parsed.path)
                if not target.exists():
                    broken_links.append(f"{md_file.relative_to(root)}: [{text}]({url_str})")
                continue
            target_path = url_str.split("#")[0]
            if not target_path:
                continue
            resolved = (md_file.parent / target_path).resolve()
            if not resolved.exists():
                broken_links.append(f"{md_file.relative_to(root)}: [{text}]({url_str}) -> {resolved}")

    assert not broken_links, f"Broken markdown links detected: {broken_links}"

def test_cli_reference_matches_parser() -> None:
    root = _get_project_root()
    cli_doc = root / "docs" / "reference" / "cli.md"
    assert cli_doc.exists()
    content = cli_doc.read_text(encoding="utf-8")

    parser = build_parser()
    tree = _build_command_option_tree(parser)

    expected_commands = [
        "",
        "probe",
        "probe list",
        "list",
        "run",
        "catalog",
        "catalog validate",
        "catalog list",
        "catalog show",
        "catalog coverage",
        "catalog parameter-coverage",
        "catalog check",
        "matrix",
        "matrix preview",
        "matrix estimate",
        "matrix run",
        "matrix coverage",
        "matrix preview-parameters",
    ]
    for cmd in expected_commands:
        assert cmd in tree, f"Command '{cmd}' missing from parser tree"

    flag_pattern = re.compile(r"(`(--[a-z0-9-]+)`)")
    documented_flags = {match[1] for match in flag_pattern.findall(content)}

    all_parser_flags: set[str] = set()
    for opts in tree.values():
        all_parser_flags.update(opts)

    for flag in documented_flags:
        assert flag in all_parser_flags, f"Documented flag '{flag}' not found in any parser command"

def test_no_unredacted_secrets_in_docs() -> None:
    root = _get_project_root()
    md_files = list((root / "docs").rglob("*.md")) + [root / "README.md"]
    forbidden_secret_patterns = [
        re.compile(r"\"private_key\":\s*\"(?!\[REDACTED\])[A-Za-z0-9+/=]{40,}\""),
        re.compile(r"\"psk\":\s*\"(?!\[REDACTED\])[A-Za-z0-9+/=]{40,}\""),
    ]
    for md in md_files:
        content = md.read_text(encoding="utf-8")
        for pat in forbidden_secret_patterns:
            assert not pat.search(content), f"Unredacted secret pattern detected in {md.relative_to(root)}"

def test_all_eight_profile_families_documented() -> None:
    root = _get_project_root()
    expected_profiles = [
        "vless_tcp_none",
        "vless_tcp_reality",
        "vmess_ws_tls",
        "trojan_tcp_tls",
        "shadowsocks_tcp_none",
        "wireguard_udp_none",
        "openvpn_tcp_none",
        "amneziawg_udp_none",
    ]
    matrix_doc = (root / "docs" / "feature-matrix.md").read_text(encoding="utf-8")
    config_doc = (root / "docs" / "reference" / "configuration.md").read_text(encoding="utf-8")

    for profile in expected_profiles:
        assert profile in matrix_doc, f"Profile '{profile}' missing from feature-matrix.md"
        assert profile in config_doc, f"Profile '{profile}' missing from configuration.md"

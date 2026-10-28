
from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any
import uuid

from connscope.core import ProbeResult, ProbeStatus, Target
from .base import EngineAdapter
from .models import AdapterCapability, AdapterMetadata, AdapterResultDetails, FailureStage, ProtocolType, TunnelExecutionMode
from .security import redact_sensitive_data, safe_temporary_workspace

@dataclass(frozen=True, slots=True)
class Layer3TunnelState:

    interface_name: str
    interface_up: bool
    peer_endpoint: str | None = None
    latest_handshake_timestamp: float = 0.0
    rx_bytes: int = 0
    tx_bytes: int = 0

@dataclass(frozen=True, slots=True)
class Layer3WorkloadResult:

    traffic_traversed: bool
    data_transfer_completed: bool
    handshake_ms: float
    data_transfer_ms: float
    rx_delta: int = 0
    tx_delta: int = 0
    http_status: int | None = None
    error_message: str | None = None

@dataclass(frozen=True, slots=True)
class HostNetworkSnapshot:

    interfaces: tuple[str, ...]
    routes: str
    ip_forwarding: str | None
    wireguard_interfaces: tuple[str, ...]
    tun_interfaces: tuple[str, ...] = ()

    @classmethod
    def capture(cls) -> HostNetworkSnapshot:
        ifaces: list[str] = []
        try:
            ifaces = sorted(os.listdir("/sys/class/net"))
        except OSError:
            pass

        wg_ifaces: list[str] = []
        for iface in ifaces:
            try:
                uevent_path = Path(f"/sys/class/net/{iface}/uevent")
                if uevent_path.exists():
                    uevent = uevent_path.read_text(encoding="utf-8")
                    if "DEVTYPE=wireguard" in uevent or "DEVTYPE=amneziawg" in uevent or iface.startswith("wg") or iface.startswith("awg"):
                        wg_ifaces.append(iface)
            except OSError:
                pass

        tun_ifaces: list[str] = [i for i in ifaces if i.startswith("tun") or i.startswith("tap")]

        routes_out = ""
        ip_path = shutil.which("ip")
        if ip_path:
            import subprocess
            try:
                res = subprocess.run([ip_path, "route", "show"], capture_output=True, text=True, timeout=2.0)
                routes_out = res.stdout.strip()
            except Exception:
                pass

        fwd_val = None
        fwd_path = Path("/proc/sys/net/ipv4/ip_forward")
        if fwd_path.exists():
            try:
                fwd_val = fwd_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass

        return cls(
            interfaces=tuple(ifaces),
            routes=routes_out,
            ip_forwarding=fwd_val,
            wireguard_interfaces=tuple(sorted(wg_ifaces)),
            tun_interfaces=tuple(sorted(tun_ifaces)),
        )

    def assert_unchanged(self, after: HostNetworkSnapshot) -> None:
        new_ifaces = set(after.interfaces) - set(self.interfaces)
        missing_ifaces = set(self.interfaces) - set(after.interfaces)
        if new_ifaces:
            raise AssertionError(f"Host network leaked new interfaces: {sorted(new_ifaces)}")
        if missing_ifaces:
            raise AssertionError(f"Host network lost existing interfaces: {sorted(missing_ifaces)}")

        new_wg = set(after.wireguard_interfaces) - set(self.wireguard_interfaces)
        if new_wg:
            raise AssertionError(f"Host leaked WireGuard interface(s): {sorted(new_wg)}")

        new_tun = set(after.tun_interfaces) - set(self.tun_interfaces)
        if new_tun:
            raise AssertionError(f"Host leaked TUN/TAP interface(s): {sorted(new_tun)}")

        if after.routes != self.routes:
            raise AssertionError("Host routing table was modified during execution")

        if after.ip_forwarding != self.ip_forwarding:
            raise AssertionError(f"Host IP forwarding changed from {self.ip_forwarding} to {after.ip_forwarding}")

class Layer3IsolationBackend(ABC):

    @abstractmethod
    def check_capabilities(self) -> tuple[bool, str | None]:
        raise NotImplementedError

    @abstractmethod
    async def prepare(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def setup_interface(
        self,
        config_path: Path,
        interface_name: str,
        config: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[bool, str | None]:
        raise NotImplementedError

    @abstractmethod
    async def get_tunnel_state(
        self,
        interface_name: str,
        context: dict[str, Any],
    ) -> Layer3TunnelState:
        raise NotImplementedError

    @abstractmethod
    async def execute_workload(
        self,
        target: Target,
        test_url: str,
        timeout_s: float,
        interface_name: str,
        config: dict[str, Any],
        context: dict[str, Any],
    ) -> Layer3WorkloadResult:
        raise NotImplementedError

    @abstractmethod
    async def teardown(self, context: dict[str, Any]) -> None:
        raise NotImplementedError

class MockLayer3IsolationBackend(Layer3IsolationBackend):

    def __init__(
        self,
        *,
        should_pass_capabilities: bool = True,
        capability_error: str | None = None,
        should_pass_setup: bool = True,
        setup_error: str | None = None,
        should_handshake: bool = True,
        handshake_delay_ms: float = 20.0,
        handshake_age_s: float = 1.0,
        should_traverse_traffic: bool = True,
        should_complete_data_transfer: bool = True,
        http_status: int = 204,
        data_transfer_error: str | None = None,
        initial_rx: int = 100,
        initial_tx: int = 150,
        rx_delta: int = 1024,
        tx_delta: int = 512,
        origin_namespace_mode: bool = False,
        should_pass_origin_route: bool = True,
        should_pass_link_add_origin: bool = True,
        should_pass_move_netns: bool = True,
        driver: Layer3DeviceDriver | None = None,
        driver_name: str | None = None,
    ) -> None:
        self.should_pass_capabilities = should_pass_capabilities
        self.capability_error = capability_error
        self.should_pass_setup = should_pass_setup
        self.setup_error = setup_error
        self.should_handshake = should_handshake
        self.handshake_delay_ms = handshake_delay_ms
        self.handshake_age_s = handshake_age_s
        self.should_traverse_traffic = should_traverse_traffic
        self.should_complete_data_transfer = should_complete_data_transfer
        self.http_status = http_status
        self.data_transfer_error = data_transfer_error
        self.initial_rx = initial_rx
        self.initial_tx = initial_tx
        self.rx_delta = rx_delta
        self.tx_delta = tx_delta

        if driver is not None:
            self.driver_name = driver.driver_name
        elif driver_name is not None:
            self.driver_name = driver_name
        else:
            self.driver_name = "wireguard"

        self.origin_namespace_mode = origin_namespace_mode
        self.should_pass_origin_route = should_pass_origin_route
        self.should_pass_link_add_origin = should_pass_link_add_origin
        self.should_pass_move_netns = should_pass_move_netns
        self.created_in_origin = False
        self.moved_to_netns = False
        self.origin_endpoint_route: str | None = None

        self.prepare_called = False
        self.setup_called = False
        self.workload_called = False
        self.teardown_called = False
        self.events: list[str] = []

        self.applied_mtu: int | None = None
        self.assigned_addresses: list[str] = []
        self.configured_routes: list[str] = []
        self.wg_setconf_content: str | None = None
        self.amnezia_parameters: dict[str, Any] = {}
        self.openvpn_parameters: dict[str, Any] = {}

    def check_capabilities(self) -> tuple[bool, str | None]:
        if not self.should_pass_capabilities:
            return False, self.capability_error or "Mock capability failure"
        return True, None

    async def prepare(self) -> dict[str, Any]:
        self.prepare_called = True
        self.events.append("prepare")
        if self.driver_name == "amneziawg":
            iface = "awg-mock0"
        elif self.driver_name == "openvpn":
            iface = "tun-mock0"
        else:
            iface = "wg-mock0"
        ctx = {
            "netns_name": f"mock-netns-{uuid.uuid4().hex[:8]}",
            "interface_name": iface,
            "isolation_mode": "origin_netns" if self.origin_namespace_mode else "netns",
        }
        return ctx

    async def setup_interface(
        self,
        config_path: Path,
        interface_name: str,
        config: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[bool, str | None]:
        self.setup_called = True
        self.events.append("setup_interface")

        if self.origin_namespace_mode:
            if self.driver_name == "openvpn":
                return False, "Driver 'openvpn' does not support origin-namespace socket placement"

            context["isolation_mode"] = "origin_netns"
            endpoint = config.get("endpoint", "198.51.100.1:51820")
            if not self.should_pass_origin_route:
                return False, f"Outer WireGuard endpoint '{endpoint}' has no route in origin namespace"
            self.origin_endpoint_route = f"{endpoint} via 192.168.1.1 dev eth0 src 192.168.1.50"
            context["origin_endpoint_route"] = self.origin_endpoint_route

            if not self.should_pass_link_add_origin:
                return False, f"Failed to create WireGuard interface '{interface_name}' in origin namespace"
            self.created_in_origin = True
            context["created_in_origin"] = True

            if not self.should_pass_move_netns:
                return False, f"Failed to move WireGuard interface '{interface_name}' into namespace"
            self.moved_to_netns = True
            context["moved_to_netns"] = True

        if config_path.is_file():
            content = config_path.read_text(encoding="utf-8")
            if self.driver_name == "openvpn":
                for line in content.splitlines():
                    line_clean = line.strip().lower()
                    for unsafe in ("up ", "down ", "script-security", "plugin ", "config ", "redirect-gateway"):
                        if line_clean.startswith(unsafe):
                            return False, f"OpenVPN rejected unsafe directive '{unsafe.strip()}' in configuration"
                    if "`" in line or "$(" in line:
                        return False, "OpenVPN rejected command substitution syntax in configuration"

                for line in content.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        self.openvpn_parameters[parts[0].lower()] = parts[1]
            else:
                self.wg_setconf_content = content
                tool = "awg" if self.driver_name == "amneziawg" else "wg"
                if "Address =" in content or "MTU =" in content or "DNS =" in content:
                    return False, f"{tool} setconf rejected invalid configuration: Address/MTU/DNS must not be present in {tool} setconf files"

                if self.driver_name == "amneziawg":
                    for line in content.splitlines():
                        if "=" in line:
                            k, v = [x.strip() for x in line.split("=", 1)]
                            if k.lower() in {"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"}:
                                self.amnezia_parameters[k.lower()] = int(v) if v.isdigit() else v

        self.applied_mtu = config.get("tun_mtu", config.get("mtu", 1500 if self.driver_name == "openvpn" else 1420))
        self.assigned_addresses = [a.strip() for a in config.get("address", "10.0.0.2/32").split(",") if a.strip()]
        self.configured_routes = [r.strip() for r in config.get("allowed_ips", "0.0.0.0/0, ::/0").split(",") if r.strip()]

        if not self.should_pass_setup:
            return False, self.setup_error or "Mock interface creation failed"
        return True, None

    async def get_tunnel_state(
        self,
        interface_name: str,
        context: dict[str, Any],
    ) -> Layer3TunnelState:
        now = time.time()
        hs_time = (now - self.handshake_age_s) if self.should_handshake else 0.0
        return Layer3TunnelState(
            interface_name=interface_name,
            interface_up=True,
            peer_endpoint=context.get("peer_endpoint", "192.0.2.1:51820"),
            latest_handshake_timestamp=hs_time,
            rx_bytes=self.initial_rx,
            tx_bytes=self.initial_tx,
        )

    async def execute_workload(
        self,
        target: Target,
        test_url: str,
        timeout_s: float,
        interface_name: str,
        config: dict[str, Any],
        context: dict[str, Any],
    ) -> Layer3WorkloadResult:
        self.workload_called = True
        self.events.append("execute_workload")
        if self.handshake_delay_ms > 0:
            await asyncio.sleep(min(0.05, self.handshake_delay_ms / 1000.0))

        if not self.should_traverse_traffic:
            return Layer3WorkloadResult(
                traffic_traversed=False,
                data_transfer_completed=False,
                handshake_ms=self.handshake_delay_ms,
                data_transfer_ms=0.0,
                rx_delta=0,
                tx_delta=100,
                http_status=None,
                error_message="Workload traffic not received back through tunnel",
            )

        if not self.should_complete_data_transfer:
            return Layer3WorkloadResult(
                traffic_traversed=True,
                data_transfer_completed=False,
                handshake_ms=self.handshake_delay_ms,
                data_transfer_ms=25.0,
                rx_delta=self.rx_delta,
                tx_delta=self.tx_delta,
                http_status=self.http_status if self.http_status != 204 else 500,
                error_message=self.data_transfer_error or f"HTTP request failed with status {self.http_status}",
            )

        return Layer3WorkloadResult(
            traffic_traversed=True,
            data_transfer_completed=True,
            handshake_ms=self.handshake_delay_ms,
            data_transfer_ms=30.0,
            rx_delta=self.rx_delta,
            tx_delta=self.tx_delta,
            http_status=204,
            error_message=None,
        )

    async def teardown(self, context: dict[str, Any]) -> None:
        self.teardown_called = True
        self.events.append("teardown")
        if context.get("created_in_origin") and not context.get("moved_to_netns"):
            self.events.append("cleaned_up_origin_interface")
        elif context.get("moved_to_netns"):
            self.events.append("cleaned_up_netns_interface")
        elif self.driver_name == "openvpn":
            self.events.append("cleaned_up_tun_interface")

class Layer3DeviceDriver(ABC):

    @property
    @abstractmethod
    def driver_name(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def link_type(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def tool_binary(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def default_interface_prefix(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def opt_in_env_var(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def origin_netns_env_var(self) -> str:
        raise NotImplementedError

    @property
    def supports_origin_netns(self) -> bool:
        return True

    @abstractmethod
    def check_capabilities(self, require_origin_netns: bool = False) -> tuple[bool, str | None]:
        raise NotImplementedError

    @abstractmethod
    async def create_interface(
        self,
        interface_name: str,
        netns_name: str | None = None,
    ) -> tuple[bool, str | None]:
        raise NotImplementedError

    @abstractmethod
    async def apply_config(
        self,
        interface_name: str,
        config_path: Path,
        netns_name: str | None = None,
    ) -> tuple[bool, str | None]:
        raise NotImplementedError

    @abstractmethod
    async def read_tunnel_state(
        self,
        interface_name: str,
        netns_name: str | None = None,
    ) -> tuple[float, int, int]:
        raise NotImplementedError

class WireGuardDeviceDriver(Layer3DeviceDriver):

    @property
    def driver_name(self) -> str:
        return "wireguard"

    @property
    def link_type(self) -> str:
        return "wireguard"

    @property
    def tool_binary(self) -> str:
        return "wg"

    @property
    def default_interface_prefix(self) -> str:
        return "wg-cs-"

    @property
    def opt_in_env_var(self) -> str:
        return "CONNSCOPE_ENABLE_REAL_WIREGUARD"

    @property
    def origin_netns_env_var(self) -> str:
        return "CONNSCOPE_WIREGUARD_ORIGIN_NETNS"

    def check_capabilities(self, require_origin_netns: bool = False) -> tuple[bool, str | None]:
        if require_origin_netns and os.environ.get("CONNSCOPE_WIREGUARD_ORIGIN_NETNS", "0") != "1":
            return (
                False,
                "WireGuard origin-namespace isolation requires explicit opt-in (CONNSCOPE_WIREGUARD_ORIGIN_NETNS=1)",
            )
        opt_in = (
            os.environ.get("CONNSCOPE_ENABLE_REAL_WIREGUARD", "0") == "1"
            or os.environ.get("CONNSCOPE_TEST_REAL_WIREGUARD", "0") == "1"
        )
        if not opt_in:
            return (
                False,
                "Real WireGuard interface creation requires explicit opt-in "
                "(CONNSCOPE_ENABLE_REAL_WIREGUARD=1 or CONNSCOPE_TEST_REAL_WIREGUARD=1)",
            )

        if not sys.platform.startswith("linux"):
            return False, f"Network namespace isolation is only supported on Linux (running on {sys.platform})"

        if os.geteuid() != 0:
            return (
                False,
                "Origin network namespace interface management requires root / CAP_NET_ADMIN privileges"
                if require_origin_netns
                else "Network namespace interface management requires root / CAP_NET_ADMIN privileges",
            )

        ip_bin = shutil.which("ip")
        if not ip_bin:
            return False, "Required executable 'ip' not found in PATH"

        wg_bin = shutil.which("wg")
        if not wg_bin:
            return False, "Required executable 'wg' not found in PATH"

        return True, None

    async def create_interface(
        self,
        interface_name: str,
        netns_name: str | None = None,
    ) -> tuple[bool, str | None]:
        cmd = ["ip"]
        if netns_name:
            cmd.extend(["netns", "exec", netns_name, "ip"])
        cmd.extend(["link", "add", "dev", interface_name, "type", "wireguard"])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"Failed to create wireguard interface '{interface_name}': {stderr.decode('utf-8', errors='replace').strip()}"
        return True, None

    async def apply_config(
        self,
        interface_name: str,
        config_path: Path,
        netns_name: str | None = None,
    ) -> tuple[bool, str | None]:
        cmd = []
        if netns_name:
            cmd.extend(["ip", "netns", "exec", netns_name])
        cmd.extend(["wg", "setconf", interface_name, str(config_path)])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"wg setconf failed for '{interface_name}': {stderr.decode('utf-8', errors='replace').strip()}"
        return True, None

    async def read_tunnel_state(
        self,
        interface_name: str,
        netns_name: str | None = None,
    ) -> tuple[float, int, int]:
        cmd_hs = []
        if netns_name:
            cmd_hs.extend(["ip", "netns", "exec", netns_name])
        cmd_hs.extend(["wg", "show", interface_name, "latest-handshakes"])

        proc = await asyncio.create_subprocess_exec(
            *cmd_hs,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode("utf-8", errors="replace").strip().splitlines()
        latest_ts = 0.0
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                try:
                    latest_ts = float(parts[1])
                except ValueError:
                    latest_ts = 0.0

        cmd_tr = []
        if netns_name:
            cmd_tr.extend(["ip", "netns", "exec", netns_name])
        cmd_tr.extend(["wg", "show", interface_name, "transfer"])

        proc_tr = await asyncio.create_subprocess_exec(
            *cmd_tr,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_tr, _ = await proc_tr.communicate()
        rx_bytes, tx_bytes = 0, 0
        tr_lines = stdout_tr.decode("utf-8", errors="replace").strip().splitlines()
        if tr_lines:
            parts = tr_lines[0].split()
            if len(parts) >= 3:
                try:
                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[2])
                except ValueError:
                    pass

        return latest_ts, rx_bytes, tx_bytes

class AmneziaWGDeviceDriver(Layer3DeviceDriver):

    @property
    def driver_name(self) -> str:
        return "amneziawg"

    @property
    def link_type(self) -> str:
        return "amneziawg"

    @property
    def tool_binary(self) -> str:
        return "awg"

    @property
    def default_interface_prefix(self) -> str:
        return "awg-cs-"

    @property
    def opt_in_env_var(self) -> str:
        return "CONNSCOPE_ENABLE_REAL_AMNEZIAWG"

    @property
    def origin_netns_env_var(self) -> str:
        return "CONNSCOPE_AMNEZIAWG_ORIGIN_NETNS"

    def check_capabilities(self, require_origin_netns: bool = False) -> tuple[bool, str | None]:
        if require_origin_netns and os.environ.get("CONNSCOPE_AMNEZIAWG_ORIGIN_NETNS", "0") != "1":
            return (
                False,
                "AmneziaWG origin-namespace isolation requires explicit opt-in (CONNSCOPE_AMNEZIAWG_ORIGIN_NETNS=1)",
            )
        opt_in = (
            os.environ.get("CONNSCOPE_ENABLE_REAL_AMNEZIAWG", "0") == "1"
            or os.environ.get("CONNSCOPE_TEST_REAL_AMNEZIAWG", "0") == "1"
        )
        if not opt_in:
            return (
                False,
                "Real AmneziaWG interface creation requires explicit opt-in "
                "(CONNSCOPE_ENABLE_REAL_AMNEZIAWG=1 or CONNSCOPE_TEST_REAL_AMNEZIAWG=1)",
            )

        if not sys.platform.startswith("linux"):
            return False, f"AmneziaWG isolation is only supported on Linux (running on {sys.platform})"

        if os.geteuid() != 0:
            return (
                False,
                "Origin network namespace interface management requires root / CAP_NET_ADMIN privileges"
                if require_origin_netns
                else "AmneziaWG interface management requires root / CAP_NET_ADMIN privileges",
            )

        ip_bin = shutil.which("ip")
        if not ip_bin:
            return False, "Required executable 'ip' not found in PATH"

        awg_bin = shutil.which("awg")
        if not awg_bin:
            return False, "Required executable 'awg' not found in PATH"

        mod_path = Path("/sys/module/amneziawg")
        if not mod_path.exists():
            return False, "AmneziaWG kernel module 'amneziawg' is not loaded (/sys/module/amneziawg not found)"

        return True, None

    async def create_interface(
        self,
        interface_name: str,
        netns_name: str | None = None,
    ) -> tuple[bool, str | None]:
        cmd = ["ip"]
        if netns_name:
            cmd.extend(["netns", "exec", netns_name, "ip"])
        cmd.extend(["link", "add", "dev", interface_name, "type", "amneziawg"])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"Failed to create amneziawg interface '{interface_name}': {stderr.decode('utf-8', errors='replace').strip()}"
        return True, None

    async def apply_config(
        self,
        interface_name: str,
        config_path: Path,
        netns_name: str | None = None,
    ) -> tuple[bool, str | None]:
        cmd = []
        if netns_name:
            cmd.extend(["ip", "netns", "exec", netns_name])
        cmd.extend(["awg", "setconf", interface_name, str(config_path)])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"awg setconf failed for '{interface_name}': {stderr.decode('utf-8', errors='replace').strip()}"
        return True, None

    async def read_tunnel_state(
        self,
        interface_name: str,
        netns_name: str | None = None,
    ) -> tuple[float, int, int]:
        cmd_hs = []
        if netns_name:
            cmd_hs.extend(["ip", "netns", "exec", netns_name])
        cmd_hs.extend(["awg", "show", interface_name, "latest-handshakes"])

        proc = await asyncio.create_subprocess_exec(
            *cmd_hs,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode("utf-8", errors="replace").strip().splitlines()
        latest_ts = 0.0
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                try:
                    latest_ts = float(parts[1])
                except ValueError:
                    latest_ts = 0.0

        cmd_tr = []
        if netns_name:
            cmd_tr.extend(["ip", "netns", "exec", netns_name])
        cmd_tr.extend(["awg", "show", interface_name, "transfer"])

        proc_tr = await asyncio.create_subprocess_exec(
            *cmd_tr,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_tr, _ = await proc_tr.communicate()
        rx_bytes, tx_bytes = 0, 0
        tr_lines = stdout_tr.decode("utf-8", errors="replace").strip().splitlines()
        if tr_lines:
            parts = tr_lines[0].split()
            if len(parts) >= 3:
                try:
                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[2])
                except ValueError:
                    pass

        return latest_ts, rx_bytes, tx_bytes

class OpenVPNDeviceDriver(Layer3DeviceDriver):

    @property
    def driver_name(self) -> str:
        return "openvpn"

    @property
    def link_type(self) -> str:
        return "tun"

    @property
    def tool_binary(self) -> str:
        return "openvpn"

    @property
    def default_interface_prefix(self) -> str:
        return "tun-cs-"

    @property
    def opt_in_env_var(self) -> str:
        return "CONNSCOPE_ENABLE_REAL_OPENVPN"

    @property
    def origin_netns_env_var(self) -> str:
        return "CONNSCOPE_OPENVPN_ORIGIN_NETNS"

    @property
    def supports_origin_netns(self) -> bool:
        return False

    def check_capabilities(self, require_origin_netns: bool = False) -> tuple[bool, str | None]:
        if require_origin_netns:
            return (
                False,
                "OpenVPN is a userspace daemon; origin-namespace socket placement is not supported "
                "(outer socket belongs to a userspace process, not kernel device layer)",
            )
        opt_in = (
            os.environ.get("CONNSCOPE_ENABLE_REAL_OPENVPN", "0") == "1"
            or os.environ.get("CONNSCOPE_TEST_REAL_OPENVPN", "0") == "1"
        )
        if not opt_in:
            return (
                False,
                "Real OpenVPN interface creation requires explicit opt-in "
                "(CONNSCOPE_ENABLE_REAL_OPENVPN=1 or CONNSCOPE_TEST_REAL_OPENVPN=1)",
            )

        if not sys.platform.startswith("linux"):
            return False, f"Network namespace isolation is only supported on Linux (running on {sys.platform})"

        if os.geteuid() != 0:
            return (
                False,
                "Network namespace interface management requires root / CAP_NET_ADMIN privileges",
            )

        ovpn_bin = resolve_safe_executable("openvpn")
        if not ovpn_bin:
            return False, "Required executable 'openvpn' not found in allowlisted lookup paths"

        ip_bin = shutil.which("ip")
        if not ip_bin:
            return False, "Required executable 'ip' not found in PATH"

        return (
            False,
            "OpenVPN userspace process cannot reach external endpoint from an isolated netns without "
            "host NAT/forwarding (which violates ConnScope host safety invariants); live tunnel execution "
            "remains safely disabled and unclaimed",
        )

    async def create_interface(
        self,
        interface_name: str,
        netns_name: str | None = None,
    ) -> tuple[bool, str | None]:
        return True, None

    async def apply_config(
        self,
        interface_name: str,
        config_path: Path,
        netns_name: str | None = None,
    ) -> tuple[bool, str | None]:
        return True, None

    async def read_tunnel_state(
        self,
        interface_name: str,
        netns_name: str | None = None,
    ) -> tuple[float, int, int]:
        return 0.0, 0, 0

class LinuxNetnsIsolationBackend(Layer3IsolationBackend):

    def __init__(self, driver: Layer3DeviceDriver | None = None) -> None:
        self.driver: Layer3DeviceDriver = driver if driver is not None else WireGuardDeviceDriver()

    def check_capabilities(self) -> tuple[bool, str | None]:
        return self.driver.check_capabilities(require_origin_netns=False)

    async def prepare(self) -> dict[str, Any]:
        prefix = self.driver.driver_name[:3]
        netns_name = f"cs-{prefix}-{uuid.uuid4().hex[:8]}"
        interface_name = f"{self.driver.default_interface_prefix}{uuid.uuid4().hex[:6]}"

        proc = await asyncio.create_subprocess_exec(
            "ip", "netns", "add", netns_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to create network namespace '{netns_name}': {stderr.decode('utf-8', errors='replace').strip()}")

        try:
            proc_lo = await asyncio.create_subprocess_exec(
                "ip", "netns", "exec", netns_name, "ip", "link", "set", "dev", "lo", "up",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_lo = await proc_lo.communicate()
            if proc_lo.returncode != 0:
                raise RuntimeError(f"Failed to bring up loopback in '{netns_name}': {stderr_lo.decode('utf-8', errors='replace').strip()}")
        except Exception:
            await self.teardown({"netns_name": netns_name})
            raise

        return {
            "netns_name": netns_name,
            "interface_name": interface_name,
        }

    async def setup_interface(
        self,
        config_path: Path,
        interface_name: str,
        config: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[bool, str | None]:
        netns_name = context.get("netns_name")
        if not netns_name:
            return False, "Missing network namespace name in context"

        proc_ok, proc_err = await self.driver.create_interface(interface_name, netns_name=netns_name)
        if not proc_ok:
            return False, proc_err

        proc_wg_ok, proc_wg_err = await self.driver.apply_config(interface_name, config_path, netns_name=netns_name)
        if not proc_wg_ok:
            return False, proc_wg_err

        mtu = int(config.get("mtu", 1420))
        proc_mtu = await asyncio.create_subprocess_exec(
            "ip", "netns", "exec", netns_name,
            "ip", "link", "set", "dev", interface_name, "mtu", str(mtu),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_mtu = await proc_mtu.communicate()
        if proc_mtu.returncode != 0:
            return False, f"Failed to set MTU {mtu} on '{interface_name}': {stderr_mtu.decode('utf-8', errors='replace').strip()}"

        addr_str = config.get("address", "10.0.0.2/32")
        addresses = [a.strip() for a in addr_str.split(",") if a.strip()]
        for addr in addresses:
            proc_addr = await asyncio.create_subprocess_exec(
                "ip", "netns", "exec", netns_name,
                "ip", "addr", "add", addr, "dev", interface_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_addr = await proc_addr.communicate()
            if proc_addr.returncode != 0 and b"File exists" not in stderr_addr:
                return False, f"Failed to assign address '{addr}' to '{interface_name}': {stderr_addr.decode('utf-8', errors='replace').strip()}"

        proc_up = await asyncio.create_subprocess_exec(
            "ip", "netns", "exec", netns_name,
            "ip", "link", "set", "dev", interface_name, "up",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_up = await proc_up.communicate()
        if proc_up.returncode != 0:
            return False, f"Failed to bring up interface '{interface_name}': {stderr_up.decode('utf-8', errors='replace').strip()}"

        allowed_ips_str = config.get("allowed_ips", "0.0.0.0/0, ::/0")
        for cidr_raw in allowed_ips_str.split(","):
            cidr = cidr_raw.strip()
            if not cidr:
                continue
            if cidr == "0.0.0.0/0":
                route_cmd = ["ip", "netns", "exec", netns_name, "ip", "route", "add", "default", "dev", interface_name]
            elif cidr == "::/0":
                route_cmd = ["ip", "netns", "exec", netns_name, "ip", "-6", "route", "add", "default", "dev", interface_name]
            elif ":" in cidr:
                route_cmd = ["ip", "netns", "exec", netns_name, "ip", "-6", "route", "add", cidr, "dev", interface_name]
            else:
                route_cmd = ["ip", "netns", "exec", netns_name, "ip", "route", "add", cidr, "dev", interface_name]

            proc_route = await asyncio.create_subprocess_exec(
                *route_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_route = await proc_route.communicate()
            if proc_route.returncode != 0 and b"File exists" not in stderr_route:
                pass

        endpoint = config.get("endpoint", "")
        endpoint_host = endpoint.rsplit(":", 1)[0].strip("[]") if ":" in endpoint else endpoint
        outer_reachable = False
        if endpoint_host:
            proc_check = await asyncio.create_subprocess_exec(
                "ip", "netns", "exec", netns_name,
                "ip", "route", "get", endpoint_host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_chk, _ = await proc_check.communicate()
            if proc_check.returncode == 0 and interface_name.encode() not in stdout_chk:
                outer_reachable = True

        context["outer_endpoint_reachable"] = outer_reachable

        return True, None

    async def get_tunnel_state(
        self,
        interface_name: str,
        context: dict[str, Any],
    ) -> Layer3TunnelState:
        netns_name = context.get("netns_name")
        if not netns_name:
            return Layer3TunnelState(interface_name=interface_name, interface_up=False)

        latest_ts, rx_bytes, tx_bytes = await self.driver.read_tunnel_state(interface_name, netns_name=netns_name)

        return Layer3TunnelState(
            interface_name=interface_name,
            interface_up=True,
            latest_handshake_timestamp=latest_ts,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
        )

    async def execute_workload(
        self,
        target: Target,
        test_url: str,
        timeout_s: float,
        interface_name: str,
        config: dict[str, Any],
        context: dict[str, Any],
    ) -> Layer3WorkloadResult:
        netns_name = context.get("netns_name")
        if not netns_name:
            return Layer3WorkloadResult(
                traffic_traversed=False,
                data_transfer_completed=False,
                handshake_ms=0.0,
                data_transfer_ms=0.0,
                error_message="Missing network namespace",
            )

        state_before = await self.get_tunnel_state(interface_name, context)

        t_start = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            "ip", "netns", "exec", netns_name,
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--max-time", str(int(max(1.0, timeout_s))),
            test_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s + 1.0)
            elapsed_ms = (time.monotonic() - t_start) * 1000.0
            http_status = None
            code_str = stdout.decode("utf-8", errors="replace").strip()
            if code_str.isdigit():
                http_status = int(code_str)

            state_after = await self.get_tunnel_state(interface_name, context)
            rx_delta = state_after.rx_bytes - state_before.rx_bytes
            tx_delta = state_after.tx_bytes - state_before.tx_bytes

            traffic_traversed = tx_delta > 0 and rx_delta > 0
            transfer_ok = (http_status in (200, 204)) if http_status else False

            return Layer3WorkloadResult(
                traffic_traversed=traffic_traversed,
                data_transfer_completed=transfer_ok,
                handshake_ms=0.0,
                data_transfer_ms=elapsed_ms,
                rx_delta=rx_delta,
                tx_delta=tx_delta,
                http_status=http_status,
                error_message=None if transfer_ok else f"HTTP code {http_status}: {stderr.decode('utf-8', errors='replace').strip()}",
            )
        except asyncio.TimeoutError:
            return Layer3WorkloadResult(
                traffic_traversed=False,
                data_transfer_completed=False,
                handshake_ms=0.0,
                data_transfer_ms=timeout_s * 1000.0,
                error_message="Workload execution timed out",
            )

    async def teardown(self, context: dict[str, Any]) -> None:
        netns_name = context.get("netns_name")
        interface_name = context.get("interface_name")

        if netns_name and interface_name:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "netns", "exec", netns_name,
                    "ip", "link", "del", "dev", interface_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
            except Exception:
                pass

        if netns_name:
            try:
                proc_ns = await asyncio.create_subprocess_exec(
                    "ip", "netns", "del", netns_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc_ns.wait()
            except Exception:
                pass

class LinuxOriginNetnsIsolationBackend(LinuxNetnsIsolationBackend):

    def __init__(self, driver: Layer3DeviceDriver | None = None) -> None:
        super().__init__(driver=driver)

    def check_capabilities(self) -> tuple[bool, str | None]:
        if not self.driver.supports_origin_netns:
            return False, f"Driver '{self.driver.driver_name}' does not support origin-namespace socket placement"
        return self.driver.check_capabilities(require_origin_netns=True)

    async def prepare(self) -> dict[str, Any]:
        context = await super().prepare()
        context["isolation_mode"] = "origin_netns"
        context["created_in_origin"] = False
        context["moved_to_netns"] = False
        return context

    async def setup_interface(
        self,
        config_path: Path,
        interface_name: str,
        config: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[bool, str | None]:
        netns_name = context.get("netns_name")
        if not netns_name:
            return False, "Missing network namespace name in context"

        endpoint = config.get("endpoint", "")
        endpoint_host = endpoint.rsplit(":", 1)[0].strip("[]") if ":" in endpoint else endpoint
        if not endpoint_host:
            return False, "Missing endpoint in WireGuard configuration"

        proc_route = await asyncio.create_subprocess_exec(
            "ip", "route", "get", endpoint_host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_route, stderr_route = await proc_route.communicate()
        if proc_route.returncode != 0:
            err_msg = stderr_route.decode("utf-8", errors="replace").strip()
            return False, f"Outer WireGuard endpoint '{endpoint_host}' has no route in origin namespace: {err_msg}"

        origin_route_str = stdout_route.decode("utf-8", errors="replace").strip().splitlines()[0] if stdout_route else ""
        context["origin_endpoint_route"] = origin_route_str

        ok_create, err_create = await self.driver.create_interface(interface_name, netns_name=None)
        if not ok_create:
            return False, err_create
        context["created_in_origin"] = True

        proc_move = await asyncio.create_subprocess_exec(
            "ip", "link", "set", "dev", interface_name, "netns", netns_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_move = await proc_move.communicate()
        if proc_move.returncode != 0:
            return False, f"Failed to move wireguard interface '{interface_name}' into namespace '{netns_name}': {stderr_move.decode('utf-8', errors='replace').strip()}"
        context["moved_to_netns"] = True

        ok_cfg, err_cfg = await self.driver.apply_config(interface_name, config_path, netns_name=netns_name)
        if not ok_cfg:
            return False, err_cfg

        mtu = int(config.get("mtu", 1420))
        proc_mtu = await asyncio.create_subprocess_exec(
            "ip", "netns", "exec", netns_name,
            "ip", "link", "set", "dev", interface_name, "mtu", str(mtu),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_mtu = await proc_mtu.communicate()
        if proc_mtu.returncode != 0:
            return False, f"Failed to set MTU {mtu} on '{interface_name}': {stderr_mtu.decode('utf-8', errors='replace').strip()}"

        addr_str = config.get("address", "10.0.0.2/32")
        addresses = [a.strip() for a in addr_str.split(",") if a.strip()]
        for addr in addresses:
            proc_addr = await asyncio.create_subprocess_exec(
                "ip", "netns", "exec", netns_name,
                "ip", "addr", "add", addr, "dev", interface_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_addr = await proc_addr.communicate()
            if proc_addr.returncode != 0 and b"File exists" not in stderr_addr:
                return False, f"Failed to assign address '{addr}' to '{interface_name}': {stderr_addr.decode('utf-8', errors='replace').strip()}"

        proc_up = await asyncio.create_subprocess_exec(
            "ip", "netns", "exec", netns_name,
            "ip", "link", "set", "dev", interface_name, "up",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_up = await proc_up.communicate()
        if proc_up.returncode != 0:
            return False, f"Failed to bring up interface '{interface_name}': {stderr_up.decode('utf-8', errors='replace').strip()}"

        allowed_ips_str = config.get("allowed_ips", "0.0.0.0/0, ::/0")
        for cidr_raw in allowed_ips_str.split(","):
            cidr = cidr_raw.strip()
            if not cidr:
                continue
            if cidr == "0.0.0.0/0":
                route_cmd = ["ip", "netns", "exec", netns_name, "ip", "route", "add", "default", "dev", interface_name]
            elif cidr == "::/0":
                route_cmd = ["ip", "netns", "exec", netns_name, "ip", "-6", "route", "add", "default", "dev", interface_name]
            elif ":" in cidr:
                route_cmd = ["ip", "netns", "exec", netns_name, "ip", "-6", "route", "add", cidr, "dev", interface_name]
            else:
                route_cmd = ["ip", "netns", "exec", netns_name, "ip", "route", "add", cidr, "dev", interface_name]

            proc_route_entry = await asyncio.create_subprocess_exec(
                *route_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_route_entry = await proc_route_entry.communicate()
            if proc_route_entry.returncode != 0 and b"File exists" not in stderr_route_entry:
                pass

        return True, None

    async def teardown(self, context: dict[str, Any]) -> None:
        netns_name = context.get("netns_name")
        interface_name = context.get("interface_name")
        created_in_origin = context.get("created_in_origin", False)
        moved_to_netns = context.get("moved_to_netns", False)

        if interface_name:
            if moved_to_netns and netns_name:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "ip", "netns", "exec", netns_name,
                        "ip", "link", "del", "dev", interface_name,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await proc.wait()
                except Exception:
                    pass
            elif created_in_origin:
                try:
                    proc_orig = await asyncio.create_subprocess_exec(
                        "ip", "link", "del", "dev", interface_name,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await proc_orig.wait()
                except Exception:
                    pass

        if netns_name:
            try:
                proc_ns = await asyncio.create_subprocess_exec(
                    "ip", "netns", "del", netns_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc_ns.wait()
            except Exception:
                pass

class Layer3TunnelAdapter(EngineAdapter, ABC):

    default_interface_name: str = "wg0"

    def __init__(self, isolation_backend: Layer3IsolationBackend | None = None) -> None:
        self._isolation_backend = isolation_backend

    def get_extra_result_details(self, config: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return {}

    @property
    def isolation_backend(self) -> Layer3IsolationBackend:
        if self._isolation_backend is None:
            self._isolation_backend = self.create_default_isolation_backend()
        return self._isolation_backend

    @abstractmethod
    def create_default_isolation_backend(self) -> Layer3IsolationBackend:
        raise NotImplementedError

    @abstractmethod
    def generate_config_file(self, config: dict[str, Any], target: Target, workspace_dir: Path) -> Path:
        raise NotImplementedError

    def check_capabilities(self) -> tuple[bool, str | None]:
        return self.isolation_backend.check_capabilities()

    async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
        started_at = datetime.now(timezone.utc)
        t_start = time.monotonic()

        try:
            validated_cfg = self.validate_config(config)
        except Exception as exc:
            duration_ms = (time.monotonic() - t_start) * 1000.0
            return self.create_failure_result(
                target=target,
                started_at=started_at,
                duration_ms=duration_ms,
                failure_stage=FailureStage.CONFIG_GENERATION,
                error=f"Configuration validation failed: {exc}",
            )

        exe_ok, exe_err = self.check_executable()
        if not exe_ok:
            duration_ms = (time.monotonic() - t_start) * 1000.0
            return self.create_failure_result(
                target=target,
                started_at=started_at,
                duration_ms=duration_ms,
                failure_stage=FailureStage.PRE_FLIGHT,
                error=f"Executable check failed: {exe_err}",
            )

        cap_ok, cap_err = self.check_capabilities()
        if not cap_ok:
            duration_ms = (time.monotonic() - t_start) * 1000.0
            return self.create_failure_result(
                target=target,
                started_at=started_at,
                duration_ms=duration_ms,
                failure_stage=FailureStage.PRE_FLIGHT,
                error=f"Capabilities check failed: {cap_err}",
            )

        with safe_temporary_workspace(prefix="connscope_l3_") as ws:
            cfg_file = self.generate_config_file(validated_cfg, target, ws)

            context: dict[str, Any] = {}
            try:
                context = await self.isolation_backend.prepare()
                interface_name = context.get("interface_name", self.default_interface_name)

                t_setup_start = time.monotonic()
                setup_ok, setup_err = await self.isolation_backend.setup_interface(
                    cfg_file, interface_name, validated_cfg, context
                )
                setup_ms = (time.monotonic() - t_setup_start) * 1000.0

                if not setup_ok:
                    duration_ms = (time.monotonic() - t_start) * 1000.0
                    return self.create_failure_result(
                        target=target,
                        started_at=started_at,
                        duration_ms=duration_ms,
                        failure_stage=FailureStage.INTERFACE_SETUP,
                        error=f"Interface establishment failed: {setup_err}",
                        extra={
                            "interface_established": False,
                            "peer_handshake_completed": False,
                            "traffic_traversed": False,
                            "execution_mode": TunnelExecutionMode.NETWORK_INTERFACE.value,
                            "interface_name": interface_name,
                            "isolation_strategy": context.get("isolation_mode", "netns"),
                            "origin_endpoint_route": context.get("origin_endpoint_route"),
                            "socket_in_origin_namespace": context.get("isolation_mode") == "origin_netns",
                            "cleanup_completed": True,
                            **self.get_extra_result_details(validated_cfg, context),
                        },
                    )

                tunnel_state = await self.isolation_backend.get_tunnel_state(interface_name, context)

                now_ts = time.time()
                has_handshake = (
                    tunnel_state.latest_handshake_timestamp > 0
                    and (now_ts - tunnel_state.latest_handshake_timestamp) <= 180.0
                )

                if not has_handshake:
                    duration_ms = (time.monotonic() - t_start) * 1000.0
                    if self.metadata and self.metadata.protocol in (ProtocolType.WIREGUARD, ProtocolType.AMNEZIA_WG):
                        handshake_err = "No WireGuard peer handshake received within timeout (latest_handshake=0)"
                    elif self.metadata and self.metadata.protocol == ProtocolType.OPENVPN:
                        handshake_err = "No OpenVPN peer handshake or TLS authentication received within timeout (latest_handshake=0)"
                    else:
                        handshake_err = "No peer handshake received within timeout (latest_handshake=0)"

                    return self.create_failure_result(
                        target=target,
                        started_at=started_at,
                        duration_ms=duration_ms,
                        failure_stage=FailureStage.HANDSHAKE,
                        error=handshake_err,
                        tunnel_established=False,
                        data_transfer_completed=False,
                        metrics={
                            "interface_setup_ms": setup_ms,
                            "latest_handshake_age_s": float(
                                now_ts - tunnel_state.latest_handshake_timestamp
                                if tunnel_state.latest_handshake_timestamp > 0
                                else -1.0
                            ),
                            "rx_bytes": float(tunnel_state.rx_bytes),
                            "tx_bytes": float(tunnel_state.tx_bytes),
                        },
                        extra={
                            "interface_established": True,
                            "peer_handshake_completed": False,
                            "traffic_traversed": False,
                            "execution_mode": TunnelExecutionMode.NETWORK_INTERFACE.value,
                            "interface_name": interface_name,
                            "isolation_strategy": context.get("isolation_mode", "netns"),
                            "origin_endpoint_route": context.get("origin_endpoint_route"),
                            "socket_in_origin_namespace": context.get("isolation_mode") == "origin_netns",
                            "latest_handshake_timestamp": tunnel_state.latest_handshake_timestamp,
                            "cleanup_completed": True,
                            **self.get_extra_result_details(validated_cfg, context),
                        },
                    )

                tunnel_established = True

                test_url = validated_cfg.get("test_url", "http://cp.cloudflare.com/generate_204")
                timeout_s = float(validated_cfg.get("timeout_s", 10.0))

                workload_res = await self.isolation_backend.execute_workload(
                    target, test_url, timeout_s, interface_name, validated_cfg, context
                )

                duration_ms = (time.monotonic() - t_start) * 1000.0

                if not workload_res.traffic_traversed:
                    return self.create_failure_result(
                        target=target,
                        started_at=started_at,
                        duration_ms=duration_ms,
                        failure_stage=FailureStage.TRAFFIC_TRAVERSAL,
                        error=workload_res.error_message or "Tunnel established but traffic traversal failed",
                        tunnel_established=True,
                        data_transfer_completed=False,
                        metrics={
                            "interface_setup_ms": setup_ms,
                            "handshake_ms": workload_res.handshake_ms,
                            "rx_delta": float(workload_res.rx_delta),
                            "tx_delta": float(workload_res.tx_delta),
                        },
                        extra={
                            "interface_established": True,
                            "peer_handshake_completed": True,
                            "traffic_traversed": False,
                            "execution_mode": TunnelExecutionMode.NETWORK_INTERFACE.value,
                            "interface_name": interface_name,
                            "isolation_strategy": context.get("isolation_mode", "netns"),
                            "origin_endpoint_route": context.get("origin_endpoint_route"),
                            "socket_in_origin_namespace": context.get("isolation_mode") == "origin_netns",
                            "latest_handshake_timestamp": tunnel_state.latest_handshake_timestamp,
                            "cleanup_completed": True,
                            **self.get_extra_result_details(validated_cfg, context),
                        },
                    )

                if not workload_res.data_transfer_completed:
                    return self.create_failure_result(
                        target=target,
                        started_at=started_at,
                        duration_ms=duration_ms,
                        failure_stage=FailureStage.DATA_TRANSFER,
                        error=workload_res.error_message or "Workload data transfer through tunnel failed",
                        tunnel_established=True,
                        data_transfer_completed=False,
                        metrics={
                            "interface_setup_ms": setup_ms,
                            "handshake_ms": workload_res.handshake_ms,
                            "data_transfer_ms": workload_res.data_transfer_ms,
                            "rx_delta": float(workload_res.rx_delta),
                            "tx_delta": float(workload_res.tx_delta),
                        },
                        extra={
                            "interface_established": True,
                            "peer_handshake_completed": True,
                            "traffic_traversed": True,
                            "execution_mode": TunnelExecutionMode.NETWORK_INTERFACE.value,
                            "interface_name": interface_name,
                            "isolation_strategy": context.get("isolation_mode", "netns"),
                            "origin_endpoint_route": context.get("origin_endpoint_route"),
                            "socket_in_origin_namespace": context.get("isolation_mode") == "origin_netns",
                            "latest_handshake_timestamp": tunnel_state.latest_handshake_timestamp,
                            "cleanup_completed": True,
                            **self.get_extra_result_details(validated_cfg, context),
                        },
                    )

                success_extra = {
                    "http_status": workload_res.http_status,
                    "verified_data_transfer": True,
                    "isolation_strategy": context.get("isolation_mode", "netns"),
                    "origin_endpoint_route": context.get("origin_endpoint_route"),
                    "socket_in_origin_namespace": context.get("isolation_mode") == "origin_netns",
                }
                success_extra.update(self.get_extra_result_details(validated_cfg, context))

                details = AdapterResultDetails(
                    adapter_id=self.metadata.adapter_id,
                    engine=self.metadata.engine.value,
                    protocol=self.metadata.protocol.value,
                    transport=self.metadata.transport.value,
                    security=self.metadata.security.value,
                    execution_mode=TunnelExecutionMode.NETWORK_INTERFACE.value,
                    tunnel_established=True,
                    data_transfer_completed=True,
                    interface_name=interface_name,
                    interface_established=True,
                    peer_handshake_completed=True,
                    traffic_traversed=True,
                    latest_handshake_timestamp=tunnel_state.latest_handshake_timestamp,
                    rx_bytes=tunnel_state.rx_bytes + workload_res.rx_delta,
                    tx_bytes=tunnel_state.tx_bytes + workload_res.tx_delta,
                    cleanup_completed=True,
                    extra=success_extra,
                )

                metrics = {
                    "interface_setup_ms": setup_ms,
                    "handshake_ms": workload_res.handshake_ms,
                    "data_transfer_ms": workload_res.data_transfer_ms,
                    "total_ms": duration_ms,
                    "rx_delta": float(workload_res.rx_delta),
                    "tx_delta": float(workload_res.tx_delta),
                }

                return self.create_result(
                    target=target,
                    status=ProbeStatus.SUCCESS,
                    started_at=started_at,
                    duration_ms=duration_ms,
                    details=details,
                    metrics=metrics,
                )

            finally:
                if context:
                    try:
                        await asyncio.shield(self.isolation_backend.teardown(context))
                    except Exception:
                        pass

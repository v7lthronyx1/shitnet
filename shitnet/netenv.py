import atexit
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import requests
from .operators import resolve_operator


VPN_PREFIXES = ("tun", "wg", "ppp", "utun", "nord", "warp", "tailscale", "proton", "xray", "sing")
VIRTUAL_IFACE_PREFIXES = ("br-", "docker", "veth", "virbr", "lxcbr", "cni", "flannel", "kube", "podman")
BYPASS_DNS_IPS = {"178.22.122.100", "185.51.200.2", "10.202.10.102", "10.202.10.202", "10.202.10.11", "78.157.42.100", "78.157.42.101"}


def list_ipv4_interfaces():
    ifaces = {}
    p_addr = subprocess.run(["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True)
    if p_addr.returncode == 0 and p_addr.stdout.strip():
        for item in json.loads(p_addr.stdout):
            name = item.get("ifname", "")
            low = name.lower()
            if not name or name == "lo" or low.startswith(VIRTUAL_IFACE_PREFIXES):
                continue
            state = str(item.get("operstate", "")).upper()
            addrs = []
            for a in item.get("addr_info", []):
                if a.get("family") == "inet" and a.get("local"):
                    addrs.append((a["local"], a.get("prefixlen", 24)))
            if addrs:
                is_vpn = low.startswith(VPN_PREFIXES)
                if not is_vpn and state == "DOWN":
                    continue
                ifaces[name] = {
                    "name": name,
                    "state": state,
                    "ip": addrs[0][0],
                    "prefixlen": addrs[0][1],
                    "is_vpn": is_vpn,
                    "gateway": None,
                    "metric": None,
                    "default_route": False,
                    "dns": [],
                }

    p_rt = subprocess.run(["ip", "-j", "-4", "route", "show"], capture_output=True, text=True)
    if p_rt.returncode == 0 and p_rt.stdout.strip():
        for rt in json.loads(p_rt.stdout):
            dev = rt.get("dev")
            if dev not in ifaces:
                continue
            dst = rt.get("dst", "")
            if dst in ("default", "0.0.0.0/1", "128.0.0.0/1"):
                ifaces[dev]["default_route"] = True
                if rt.get("gateway") and not ifaces[dev]["gateway"]:
                    ifaces[dev]["gateway"] = rt["gateway"]
                if rt.get("metric") is not None:
                    ifaces[dev]["metric"] = rt["metric"]

    for name, info in ifaces.items():
        if not info["gateway"] and not info["is_vpn"]:
            net = ipaddress.IPv4Network(f"{info['ip']}/{info['prefixlen']}", strict=False)
            if net.num_addresses >= 4:
                info["gateway"] = str(net.network_address + 1)
        info["dns"] = detect_interface_dns(name, fallback_gw=info["gateway"])

    return list(ifaces.values())


def detect_interface_dns(iface_name, fallback_gw=None):
    found = []
    if shutil.which("resolvectl"):
        p = subprocess.run(["resolvectl", "dns", iface_name], capture_output=True, text=True)
        if p.returncode == 0:
            for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", p.stdout):
                if m not in found and not m.startswith("127."):
                    found.append(m)
    if not found and shutil.which("nmcli"):
        p = subprocess.run(["nmcli", "-t", "-f", "IP4.DNS", "dev", "show", iface_name], capture_output=True, text=True)
        if p.returncode == 0:
            for line in p.stdout.splitlines():
                ip = line.split(":", 1)[-1].strip()
                if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip) and ip not in found and not ip.startswith("127."):
                    found.append(ip)
    if not found:
        try:
            txt = open("/etc/resolv.conf", "r", encoding="utf-8").read()
            for line in txt.splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2 and not parts[1].startswith("127.") and ":" not in parts[1]:
                        if parts[1] not in found:
                            found.append(parts[1])
        except Exception:
            pass
    if not found and fallback_gw:
        found.append(fallback_gw)
    return found


def pick_isp_dns(gw_ip, iface_dns=None, source_ip=None):
    if gw_ip:
        s = None
        try:
            import dns.message
            q = dns.message.make_query("example.com", "A").to_wire()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.2)
            if source_ip:
                s.bind((source_ip, 0))
            s.sendto(q, (gw_ip, 53))
            wire, _ = s.recvfrom(2048)
            if wire:
                return gw_ip
        except Exception:
            pass
        finally:
            if s:
                s.close()
    for ip in iface_dns or []:
        if ip not in BYPASS_DNS_IPS:
            return ip
    return gw_ip or ((iface_dns or ["2.189.44.85"])[0])


def auto_detect_topology():
    all_ifaces = list_ipv4_interfaces()
    vpns = [x for x in all_ifaces if x["is_vpn"]]
    phys = [x for x in all_ifaces if not x["is_vpn"]]

    phys_sorted = sorted(
        phys,
        key=lambda x: (
            0 if x["default_route"] else 1,
            0 if x["state"] == "UP" else 1,
            x["metric"] if x["metric"] is not None else 9999,
            0 if x["name"].startswith(("eth", "en", "usb", "rndis")) else 1,
        ),
    )

    isp_iface = phys_sorted[0] if phys_sorted else (all_ifaces[0] if all_ifaces else None)
    vpn_iface = None
    if vpns:
        vpns_sorted = sorted(vpns, key=lambda x: (0 if x["default_route"] else 1, x["name"]))
        vpn_iface = vpns_sorted[0]

    suggested_mode = "dual" if (isp_iface and vpn_iface) else "two-phase"
    return {
        "interfaces": all_ifaces,
        "isp_iface": isp_iface,
        "vpn_iface": vpn_iface,
        "suggested_mode": suggested_mode,
    }


def check_system_capabilities():
    tools = {}
    for bin_name in ("dumpcap", "tshark", "mtr", "curl", "ping", "ip", "pdftoppm", "pdfinfo"):
        tools[bin_name] = shutil.which(bin_name)

    dumpcap_ok = False
    dumpcap_err = ""
    if tools["dumpcap"]:
        p = subprocess.run([tools["dumpcap"], "-D"], capture_output=True, text=True)
        dumpcap_ok = p.returncode == 0
        if not dumpcap_ok:
            dumpcap_err = (p.stderr or p.stdout).strip()

    return {
        "is_root": os.geteuid() == 0,
        "tools": tools,
        "dumpcap_capture_ok": dumpcap_ok,
        "dumpcap_err": dumpcap_err,
    }


def fetch_public_ip(source_ip=None, timeout=8):
    endpoints = [
        ("https://api.ipify.org", "api.ipify.org", "104.26.13.205"),
        ("https://ifconfig.me/ip", "ifconfig.me", "34.160.111.145"),
        ("https://checkip.amazonaws.com", "checkip.amazonaws.com", "52.94.236.248"),
    ]
    for url, host, fallback_ip in endpoints:
        cmd = ["curl", "-4", "-sS", "--max-time", str(timeout)]
        if source_ip:
            cmd += ["--interface", source_ip]
        cmd.append(url)
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode == 0:
            ip = p.stdout.strip()
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
                return ip
        cmd_res = ["curl", "-4", "-sS", "--max-time", str(timeout), "--resolve", f"{host}:443:{fallback_ip}"]
        if source_ip:
            cmd_res += ["--interface", source_ip]
        cmd_res.append(url)
        p2 = subprocess.run(cmd_res, capture_output=True, text=True)
        if p2.returncode == 0:
            ip = p2.stdout.strip()
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
                return ip
    return ""


def fetch_json_path(url, source_ip=None, timeout=8):
    if source_ip:
        cmd = ["curl", "-4", "-sS", "--max-time", str(timeout), "--interface", source_ip, url]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            try:
                return json.loads(p.stdout)
            except Exception as e:
                return {"error": str(e)}
        return {"error": p.stderr.strip() or f"curl_rc_{p.returncode}"}
    try:
        r = requests.get(url, timeout=timeout)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def detect_isp_identity(public_ip, meta_source_ip=None, operator_override=None):
    ipinfo = {}
    ripe = {}
    if public_ip:
        ipinfo = fetch_json_path(f"https://ipinfo.io/{public_ip}/json", source_ip=meta_source_ip)
        ripe = fetch_json_path(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={public_ip}", source_ip=meta_source_ip)

    raw_asn = ""
    org_name = str(ipinfo.get("org", "") or "")
    prefix = ""

    m_org = re.match(r"^(AS\d+)\s*(.*)$", org_name, re.IGNORECASE)
    if m_org:
        raw_asn = m_org.group(1)
        org_name = m_org.group(2).strip()

    ripe_data = (ripe.get("data") or {}) if isinstance(ripe, dict) else {}
    if ripe_data.get("resource"):
        prefix = ripe_data["resource"]
    asns = ripe_data.get("asns") or []
    if asns and isinstance(asns, list):
        if not raw_asn and asns[0].get("asn"):
            raw_asn = f"AS{asns[0]['asn']}"
        if not org_name and asns[0].get("holder"):
            org_name = asns[0]["holder"]

    if not prefix and public_ip:
        parts = public_ip.split(".")
        if len(parts) == 4:
            prefix = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    op = resolve_operator(raw_asn, org_name=org_name, override_name=operator_override)
    return {
        "public_ip": public_ip,
        "asn": op["asn"],
        "prefix": prefix,
        "org_raw": org_name,
        "operator": op,
        "ipinfo": ipinfo,
        "ripe_prefix_overview": ripe,
    }


def is_private_or_reserved(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except Exception:
        return False


def derive_connection_type(iface_name, explicit_label=None):
    if explicit_label:
        return explicit_label
    low = (iface_name or "").lower()
    if low.startswith(("wl", "wifi")):
        return "Wi-Fi"
    if low.startswith(("usb", "rndis", "enp", "eth", "ens")):
        return "Ethernet / USB Tether"
    if low.startswith("wwan"):
        return "Cellular Modem"
    return iface_name or "Direct"


class DualRouteGuard:
    def __init__(self, iface_name, src_ip, gw_ip, enabled=True, table_id=197):
        self.iface_name = iface_name
        self.src_ip = src_ip
        self.gw_ip = gw_ip
        self.enabled = enabled
        self.table_id = table_id
        self.added_rule = False
        self.added_route = False
        self.old_rp_filter = None

    def _rule_exists(self):
        p = subprocess.run(["ip", "-4", "rule", "show"], capture_output=True, text=True)
        return f"from {self.src_ip}" in p.stdout

    def __enter__(self):
        if not self.enabled or not self.iface_name or not self.src_ip or not self.gw_ip:
            return self
        if os.geteuid() != 0:
            return self
        if self._rule_exists():
            return self

        p_rp = subprocess.run(["sysctl", "-n", f"net.ipv4.conf.{self.iface_name}.rp_filter"], capture_output=True, text=True)
        if p_rp.returncode == 0:
            val = p_rp.stdout.strip()
            if val == "1":
                self.old_rp_filter = val
                subprocess.run(["sysctl", "-q", "-w", f"net.ipv4.conf.{self.iface_name}.rp_filter=2"], check=False)

        r1 = subprocess.run(["ip", "route", "replace", "default", "via", self.gw_ip, "dev", self.iface_name, "table", str(self.table_id)], capture_output=True)
        if r1.returncode == 0:
            self.added_route = True
            r2 = subprocess.run(["ip", "rule", "add", "from", self.src_ip, "lookup", str(self.table_id), "priority", "1970"], capture_output=True)
            if r2.returncode == 0:
                self.added_rule = True
                atexit.register(self.cleanup)
        return self

    def cleanup(self):
        if self.added_rule:
            subprocess.run(["ip", "rule", "del", "from", self.src_ip, "lookup", str(self.table_id)], capture_output=True)
            self.added_rule = False
        if self.added_route:
            subprocess.run(["ip", "route", "flush", "table", str(self.table_id)], capture_output=True)
            self.added_route = False
        if self.old_rp_filter is not None:
            subprocess.run(["sysctl", "-q", "-w", f"net.ipv4.conf.{self.iface_name}.rp_filter={self.old_rp_filter}"], capture_output=True)
            self.old_rp_filter = None

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()

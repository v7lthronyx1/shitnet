import csv
import json
import os
import socket
import ssl
import struct
import subprocess
import time
from datetime import datetime, timezone
import dns.message
import dns.rdatatype
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from ..targets import DOH_SERVERS, DOT_SERVERS, FALLBACK_DOMAIN_IPS, NTP_SERVERS, QUIC_TARGETS, STUN_SERVERS, TCP_PORTS
from . import capture_pcap, resolve_control_host


FALLBACK_PROTO_IPS = {
    "portquiz.net": "35.180.86.68",
    "cloudflare-dns.com": "104.16.248.249",
    "dns.google": "8.8.8.8",
    "dns.quad9.net": "9.9.9.9",
    "dns.adguard-dns.com": "94.140.14.14",
    "dns.nextdns.io": "45.90.28.0",
    "free.shecan.ir": "178.22.122.100",
    "cloudflare-quic.com": "104.17.24.14",
    "quic.nginx.org": "3.125.197.172",
    "www.litespeedtech.com": "52.55.120.73",
    "www.gstatic.com": "142.250.186.67",
    "time.google.com": "216.239.35.0",
    "time.cloudflare.com": "162.159.200.1",
    "pool.ntp.org": "162.159.200.123",
    "time.windows.com": "20.101.57.9",
    "ntp.ubuntu.com": "185.125.190.58",
    "ir.pool.ntp.org": "5.144.132.2",
    "stun.l.google.com": "142.250.21.127",
    "stun.cloudflare.com": "162.159.207.0",
    "global.stun.twilio.com": "34.203.251.210",
    "meet-jit-si-turnrelay.jitsi.net": "18.198.180.83",
}


def resolve_target_ip(host, control_dns="1.1.1.1", can_resolve=False):
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    if can_resolve:
        ips = resolve_control_host(host, control_dns=control_dns)
        if ips:
            return ips[0]
    fb = FALLBACK_DOMAIN_IPS.get(host)
    if fb:
        return fb[0]
    return FALLBACK_PROTO_IPS.get(host)


def probe_tcp_port(ip, port, source_ip=None, timeout=2.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if source_ip:
        s.bind((source_ip, 0))
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
        return {"ok": True, "ms": round((time.monotonic() - t0) * 1000.0, 2), "err": None}
    except Exception as e:
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000.0, 2), "err": f"{type(e).__name__}: {e}"}
    finally:
        s.close()


def dot_probe(ip, sni, source_ip=None, timeout=3.5):
    res = {"tcp_ok": False, "tls_ok": False, "dns_ok": False, "ips": [], "ms": None, "err": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if source_ip:
        s.bind((source_ip, 0))
    t0 = time.monotonic()
    try:
        s.connect((ip, 853))
        res["tcp_ok"] = True
        ws = ctx.wrap_socket(s, server_hostname=sni)
        res["tls_ok"] = True
        q = dns.message.make_query("example.com", "A").to_wire()
        ws.sendall(len(q).to_bytes(2, "big") + q)
        hdr = ws.recv(2)
        if len(hdr) == 2:
            ln = int.from_bytes(hdr, "big")
            body = ws.recv(ln)
            ans = dns.message.from_wire(body)
            res["dns_ok"] = True
            for rrset in ans.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    res["ips"].extend([x.address for x in rrset])
        res["ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        ws.close()
    except Exception as e:
        res["ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        res["err"] = f"{type(e).__name__}: {e}"
        try:
            s.close()
        except Exception:
            pass
    return res


def doh_probe(ip, host_hdr, path, source_ip=None):
    if not ip:
        return {"ok": False, "err": "dns_resolve_fail"}
    url = f"https://{host_hdr}{path}?name=example.com&type=A"
    cmd = ["curl", "-4", "-sS", "-k", "--max-time", "5", "--resolve", f"{host_hdr}:443:{ip}", "-H", "Accept: application/dns-json", "-w", "\n%{http_code} %{time_total}"]
    if source_ip:
        cmd += ["--interface", source_ip]
    cmd.append(url)
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        return {"ok": False, "rc": p.returncode, "err": p.stderr.strip()}
    lines = p.stdout.strip().splitlines()
    meta = lines[-1] if lines else ""
    body = "\n".join(lines[:-1])
    return {"ok": " 200 " in f" {meta} " or meta.startswith("200"), "meta": meta, "has_answer": ('"Answer"' in body or "93.184." in body or "23.192." in body)}


def aioquic_handshake_probe(ip, host, port=443, alpn="h3", source_ip=None, timeout=3.0):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=[alpn], verify_mode=ssl.CERT_NONE)
    cfg.server_name = host
    conn = QuicConnection(configuration=cfg)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    if source_ip:
        s.bind((source_ip, 0))
    else:
        s.bind(("0.0.0.0", 0))
    local_addr = s.getsockname()
    try:
        conn.connect((ip, port), now=time.monotonic())
        for pkt, addr in conn.datagrams_to_send(now=time.monotonic()):
            s.sendto(pkt, addr)
        t0 = time.monotonic()
        while (time.monotonic() - t0) < timeout:
            data, _ = s.recvfrom(4096)
            if data:
                conn.receive_datagram(data, local_addr, now=time.monotonic())
                return {"ok": True, "reply_bytes": len(data), "ms": round((time.monotonic() - t0) * 1000.0, 2)}
        return {"ok": False, "err": "TimeoutError: timed out"}
    except Exception as e:
        return {"ok": False, "err": f"{type(e).__name__}: {e}"}
    finally:
        s.close()


def quic_curl_probe(url, host, ip, source_ip=None):
    cmd = ["curl", "-4", "-sS", "-k", "--http3-only", "--max-time", "5", "--resolve", f"{host}:443:{ip}", "-o", "/dev/null", "-w", "%{http_code} %{time_total}"]
    if source_ip:
        cmd += ["--interface", source_ip]
    cmd.append(url)
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode == 2:
        return {"ok": False, "rc": p.returncode, "out": "", "err": "curl_no_http3_support"}
    return {"ok": p.returncode == 0, "rc": p.returncode, "out": p.stdout.strip(), "err": p.stderr.strip()[:140]}


def ntp_probe(ip, source_ip=None):
    pkt = b"\x1b" + (47 * b"\x00")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.5)
    if source_ip:
        s.bind((source_ip, 0))
    t0 = time.monotonic()
    try:
        s.sendto(pkt, (ip, 123))
        data, _ = s.recvfrom(256)
        return {"ok": len(data) >= 48, "ms": round((time.monotonic() - t0) * 1000.0, 2)}
    except Exception as e:
        return {"ok": False, "err": f"{type(e).__name__}: {e}"}
    finally:
        s.close()


def stun_probe(ip, port, source_ip=None):
    tid = os.urandom(12)
    req = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + tid
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.5)
    if source_ip:
        s.bind((source_ip, 0))
    t0 = time.monotonic()
    try:
        s.sendto(req, (ip, port))
        data, _ = s.recvfrom(1024)
        return {"ok": len(data) >= 20, "reply_len": len(data), "ms": round((time.monotonic() - t0) * 1000.0, 2)}
    except Exception as e:
        return {"ok": False, "err": f"{type(e).__name__}: {e}"}
    finally:
        s.close()


def pmtu_sweep(ip, source_ip=None):
    rows = []
    for sz in [1200, 1400, 1450, 1472, 1473]:
        cmd = ["ping", "-n", "-M", "do", "-s", str(sz), "-c", "2", "-W", "2"]
        if source_ip:
            cmd += ["-I", source_ip]
        cmd.append(ip)
        p = subprocess.run(cmd, capture_output=True, text=True)
        rows.append({"payload_bytes": sz, "wire_mtu": sz + 28, "ok": "2 received" in p.stdout or "1 received" in p.stdout})
    return rows


def run_isp_phase(pcap_dir, isp_iface, src_ip, control_dns="1.1.1.1", can_resolve=False, progress_cb=None):
    pcap_path = pcap_dir / "04_protocols.pcapng"
    with capture_pcap(isp_iface, pcap_path, snaplen=512, progress_cb=progress_cb):
        if progress_cb:
            progress_cb("[Stage 4/6 Protocols] Probing PortQuiz 33 TCP ports & DoT/DoH/DoQ...")
        pq_ip = resolve_target_ip("portquiz.net", control_dns, can_resolve)
        port_results = []
        if pq_ip:
            for port in TCP_PORTS:
                port_results.append({"port": port, "isp": probe_tcp_port(pq_ip, port, source_ip=src_ip, timeout=2.5)})

        dot_results = []
        for label, ip, sni in DOT_SERVERS:
            dot_results.append({"label": label, "ip": ip, "sni": sni, "isp": dot_probe(ip, sni, source_ip=src_ip)})

        doh_results = []
        for label, host_ip, host_hdr, path in DOH_SERVERS:
            ip = resolve_target_ip(host_ip, control_dns, can_resolve)
            doh_results.append({"label": label, "ip": ip, "host_hdr": host_hdr, "path": path, "isp": doh_probe(ip, host_hdr, path, source_ip=src_ip)})

        quic_results = []
        for label, url, host in QUIC_TARGETS:
            ip = resolve_target_ip(host, control_dns, can_resolve)
            if not ip:
                continue
            port = 853 if "DoQ" in label else 443
            alpn = "doq" if "DoQ" in label else "h3"
            quic_results.append({
                "label": label,
                "host": host,
                "url": url,
                "ip": ip,
                "port": port,
                "alpn": alpn,
                "isp_aioquic": aioquic_handshake_probe(ip, host, port=port, alpn=alpn, source_ip=src_ip),
                "isp_http3": quic_curl_probe(url, host, ip, source_ip=src_ip) if url else None,
            })

        ntp_results = []
        for host in NTP_SERVERS:
            ip = resolve_target_ip(host, control_dns, can_resolve)
            if not ip:
                continue
            ntp_results.append({"host": host, "ip": ip, "isp": ntp_probe(ip, source_ip=src_ip)})

        stun_results = []
        for label, host, port in STUN_SERVERS:
            ip = resolve_target_ip(host, control_dns, can_resolve)
            if not ip:
                continue
            stun_results.append({"label": label, "host": host, "port": port, "ip": ip, "isp": stun_probe(ip, port, source_ip=src_ip)})

        pmtu_isp = pmtu_sweep("1.1.1.1", source_ip=src_ip)

    return {
        "portquiz_ip": pq_ip,
        "tcp_ports": port_results,
        "dot": dot_results,
        "doh": doh_results,
        "quic": quic_results,
        "ntp": ntp_results,
        "stun": stun_results,
        "pmtu_isp": pmtu_isp,
    }


def run_control_phase(isp_state, has_control=True, progress_cb=None):
    if progress_cb and has_control:
        progress_cb("[Stage 4/6 Protocols Control] Probing control path...")
    pq_ip = isp_state["portquiz_ip"]
    port_results = []
    for r in isp_state["tcp_ports"]:
        ctl = probe_tcp_port(pq_ip, r["port"], source_ip=None, timeout=2.5) if (has_control and pq_ip) else None
        port_results.append({"port": r["port"], "isp": r["isp"], "control": ctl})

    dot_results = []
    for r in isp_state["dot"]:
        ctl = dot_probe(r["ip"], r["sni"], source_ip=None) if has_control else None
        dot_results.append({"label": r["label"], "ip": r["ip"], "sni": r["sni"], "isp": r["isp"], "control": ctl})

    doh_results = []
    for r in isp_state["doh"]:
        ctl = doh_probe(r["ip"], r["host_hdr"], r["path"], source_ip=None) if has_control else None
        doh_results.append({"label": r["label"], "host_hdr": r["host_hdr"], "isp": r["isp"], "control": ctl})

    quic_results = []
    for r in isp_state["quic"]:
        ctl_aq = aioquic_handshake_probe(r["ip"], r["host"], port=r["port"], alpn=r["alpn"], source_ip=None) if has_control else None
        ctl_h3 = quic_curl_probe(r["url"], r["host"], r["ip"], source_ip=None) if (has_control and r["url"]) else None
        quic_results.append({
            "label": r["label"],
            "host": r["host"],
            "ip": r["ip"],
            "port": r["port"],
            "isp_aioquic": r["isp_aioquic"],
            "control_aioquic": ctl_aq,
            "isp_http3": r["isp_http3"],
            "control_http3": ctl_h3,
        })

    ntp_results = []
    for r in isp_state["ntp"]:
        ctl = ntp_probe(r["ip"], source_ip=None) if has_control else None
        ntp_results.append({"host": r["host"], "ip": r["ip"], "isp": r["isp"], "control": ctl})

    stun_results = []
    for r in isp_state["stun"]:
        ctl = stun_probe(r["ip"], r["port"], source_ip=None) if has_control else None
        stun_results.append({"label": r["label"], "host": r["host"], "port": r["port"], "ip": r["ip"], "isp": r["isp"], "control": ctl})

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "has_control": has_control,
        "portquiz_ip": pq_ip,
        "tcp_ports": port_results,
        "dot": dot_results,
        "doh": doh_results,
        "quic": quic_results,
        "ntp": ntp_results,
        "stun": stun_results,
        "pmtu_isp": isp_state["pmtu_isp"],
    }


def save_outputs(raw_dir, data):
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "04_protocols_forensics.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    with (raw_dir / "04_portquiz_matrix.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["port", "isp_ok", "isp_ms", "isp_err", "control_ok", "control_ms", "control_err"])
        for r in data["tcp_ports"]:
            ctl = r.get("control") or {}
            w.writerow([r["port"], r["isp"]["ok"], r["isp"]["ms"], r["isp"]["err"], ctl.get("ok", ""), ctl.get("ms", ""), ctl.get("err", "")])

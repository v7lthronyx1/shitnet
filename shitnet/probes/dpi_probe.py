import csv
import json
import os
import socket
import ssl
import struct
import time
from datetime import datetime, timezone
from ..targets import EVASION_TARGETS, FALLBACK_DOMAIN_IPS, SYNTHETIC_CONTROLS, SYNTHETIC_SNI_DOMAINS
from . import capture_pcap


def build_client_hello(sni, tls12=False, pad_to=0, grease_ech=False):
    rand_bytes = os.urandom(32)
    sess_id = os.urandom(32)
    ciphers = b"\x13\x01\x13\x02\x13\x03\xc0\x2f\xc0\x2b\xc0\x30\xc0\x2c\xcc\xa9\xcc\xa8"
    sni_bytes = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_ext = struct.pack("!HH", 0x0000, len(sni_entry) + 2) + struct.pack("!H", len(sni_entry)) + sni_entry
    alpn_list = b"\x02h2\x08http/1.1"
    alpn_ext = struct.pack("!HH", 0x0010, len(alpn_list) + 2) + struct.pack("!H", len(alpn_list)) + alpn_list
    sig_algs = b"\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01"
    sig_ext = struct.pack("!HH", 0x000d, len(sig_algs) + 2) + struct.pack("!H", len(sig_algs)) + sig_algs
    groups = b"\x00\x1d\x00\x17\x00\x18"
    groups_ext = struct.pack("!HH", 0x000a, len(groups) + 2) + struct.pack("!H", len(groups)) + groups
    exts = sni_ext + alpn_ext + sig_ext + groups_ext
    if not tls12:
        ver_list = b"\x03\x04\x03\x03"
        exts += struct.pack("!HH", 0x002b, len(ver_list) + 1) + bytes([len(ver_list)]) + ver_list
        key_pub = os.urandom(32)
        ks_entry = struct.pack("!HH", 0x001d, len(key_pub)) + key_pub
        exts += struct.pack("!HH", 0x0033, len(ks_entry) + 2) + struct.pack("!H", len(ks_entry)) + ks_entry
    if grease_ech:
        ech_payload = os.urandom(168)
        exts += struct.pack("!HH", 0xfe0d, len(ech_payload)) + ech_payload
    if pad_to > 0:
        cur_len = 2 + 32 + 1 + len(sess_id) + 2 + len(ciphers) + 2 + 2 + len(exts) + 4
        if cur_len < pad_to:
            pad_len = pad_to - cur_len
            exts += struct.pack("!HH", 0x0015, pad_len) + (b"\x00" * pad_len)
    body = (
        b"\x03\x03"
        + rand_bytes
        + bytes([len(sess_id)])
        + sess_id
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def classify_tls_bytes(data):
    if not data:
        return "EOF_CLOSE"
    rtype = data[0]
    if rtype == 0x16 and len(data) > 5 and data[5] == 0x02:
        return "TLS_SERVER_HELLO"
    if rtype == 0x15 and len(data) >= 7:
        return f"TLS_ALERT_{data[5]}_{data[6]}"
    if data.startswith(b"HTTP/"):
        return f"RAW_HTTP_{data.split(b'\r\n', 1)[0].decode('latin1', 'replace')}"
    return f"DATA_{rtype:#x}"


def raw_tls_probe(ip, sni, source_ip=None, mode="normal", port=443, timeout=3.2):
    res = {"ok": False, "outcome": None, "tcp_ms": None, "tls_ms": None, "error": None}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if source_ip:
            s.bind((source_ip, 0))
        t0 = time.monotonic()
        s.connect((ip, port))
        res["tcp_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        if mode == "tls12":
            hs = build_client_hello(sni, tls12=True)
        elif mode == "pad1800":
            hs = build_client_hello(sni, pad_to=1800)
        elif mode == "ech_grease":
            hs = build_client_hello(sni, grease_ech=True)
        else:
            hs = build_client_hello(sni)

        t1 = time.monotonic()
        if mode in ("normal", "tls12", "pad1800", "ech_grease"):
            s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs)
        elif mode == "split_5b":
            rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
            s.sendall(rec[:5])
            time.sleep(0.015)
            s.sendall(rec[5:])
        elif mode == "split_midsni":
            rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
            idx = rec.find(sni.encode("ascii"))
            cut = idx + max(1, len(sni) // 2) if idx > 0 else len(rec) // 2
            s.sendall(rec[:cut])
            time.sleep(0.015)
            s.sendall(rec[cut:])
        elif mode == "split_2b":
            rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for off in range(0, min(80, len(rec)), 2):
                s.sendall(rec[off : off + 2])
                time.sleep(0.002)
            if len(rec) > 80:
                s.sendall(rec[80:])
        elif mode == "rec_split_2":
            idx = hs.find(sni.encode("ascii"))
            cut = idx + max(1, len(sni) // 2) if idx > 0 else len(hs) // 2
            p1, p2 = hs[:cut], hs[cut:]
            s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(p1)) + p1)
            s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(p2)) + p2)
        elif mode == "rec_split_5":
            n = max(1, len(hs) // 5)
            chunks = [hs[i : i + n] for i in range(0, len(hs), n)]
            for c in chunks:
                s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(c)) + c)
        data = s.recv(4096)
        res["tls_ms"] = round((time.monotonic() - t1) * 1000.0, 2)
        res["outcome"] = classify_tls_bytes(data)
        res["ok"] = res["outcome"] == "TLS_SERVER_HELLO"
        s.close()
    except ConnectionResetError as e:
        res["tls_ms"] = round((time.monotonic() - t0) * 1000.0, 2) if res["tcp_ms"] else None
        res["outcome"] = "TCP_RST_INJECTED"
        res["error"] = str(e)
    except TimeoutError as e:
        res["outcome"] = "TCP_TIMEOUT" if res["tcp_ms"] is None else "TLS_TIMEOUT"
        res["error"] = str(e)
    except OSError as e:
        res["outcome"] = f"OS_ERR_{e.errno}"
        res["error"] = str(e)
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def https_status_probe(ip, host, source_ip=None, timeout=4.0):
    res = {"ok": False, "status": None, "server": None, "cert_cn": None, "snippet": None, "error": None}
    s = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if source_ip:
            s.bind((source_ip, 0))
        s.connect((ip, 443))
        ws = ctx.wrap_socket(s, server_hostname=host)
        cert = ws.getpeercert()
        if cert and "subject" in cert:
            for item in cert["subject"]:
                for k, v in item:
                    if k == "commonName":
                        res["cert_cn"] = v
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5\r\nConnection: close\r\n\r\n".encode("ascii")
        ws.sendall(req)
        raw = ws.recv(2048).decode("latin1", "replace")
        ws.close()
        first = raw.split("\r\n", 1)[0]
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            res["status"] = int(parts[1])
            res["ok"] = True
        for line in raw.split("\r\n"):
            if line.lower().startswith("server:"):
                res["server"] = line.split(":", 1)[1].strip()
        res["snippet"] = first[:100]
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def http_host_probe(ip, host, source_ip=None, timeout=2.8):
    res = {"ok": False, "status": None, "block_sig": None, "snippet": None, "error": None}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if source_ip:
            s.bind((source_ip, 0))
        s.connect((ip, 80))
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode("ascii")
        s.sendall(req)
        raw = s.recv(4096).decode("latin1", "replace")
        s.close()
        first = raw.split("\r\n", 1)[0]
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            res["status"] = int(parts[1])
            res["ok"] = True
        low = raw.lower()
        if "nsv2" in low or "mainpolicy" in low or "10.10.34." in low or "peyvandha" in low:
            res["block_sig"] = "ISP_HTTP_BLOCKPAGE_NSV2"
        elif res["status"] == 403:
            res["block_sig"] = "HTTP_403"
        res["snippet"] = raw[:200].replace("\r\n", " | ")
    except ConnectionResetError as e:
        res["block_sig"] = "TCP_RST_ON_HTTP"
        res["error"] = str(e)
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def pick_real_ip(domain, dns_row):
    ctl_ips = (dns_row.get("control_a") or {}).get("ips") or []
    if ctl_ips:
        return ctl_ips[0]
    fb = FALLBACK_DOMAIN_IPS.get(domain)
    if fb:
        return fb[0]
    gw_ips = (dns_row.get("isp_gw_a") or {}).get("ips") or []
    if gw_ips and not gw_ips[0].startswith(("10.", "192.168.", "172.16.", "216.239.38.120")):
        return gw_ips[0]
    return None


def run_isp_phase(pcap_dir, isp_iface, src_ip, dns_items, domains_pre_ips=None, progress_cb=None):
    pcap_path = pcap_dir / "02_dpi_forensics.pcapng"
    hetzner_ip = SYNTHETIC_CONTROLS[0][1]
    vultr_ip = SYNTHETIC_CONTROLS[1][1]
    evasion_modes = ["normal", "tls12", "pad1800", "ech_grease", "split_5b", "split_midsni", "split_2b", "rec_split_2", "rec_split_5"]

    with capture_pcap(isp_iface, pcap_path, snaplen=650, progress_cb=progress_cb):
        domain_dpi = []
        for idx, item in enumerate(dns_items):
            dom = item["domain"]
            cat = item["category"]
            real_ip = (domains_pre_ips or {}).get(dom) or pick_real_ip(dom, item)
            if not real_ip:
                continue
            if progress_cb and idx % 20 == 0:
                progress_cb(f"[Stage 2/6 DPI] Probing {idx + 1}/{len(dns_items)} ({dom})...")
            isp_tls = raw_tls_probe(real_ip, dom, source_ip=src_ip, mode="normal", timeout=3.0)
            isp_https = https_status_probe(real_ip, dom, source_ip=src_ip, timeout=3.5) if isp_tls["ok"] else None
            isp_http = http_host_probe(real_ip, dom, source_ip=src_ip, timeout=2.5)
            domain_dpi.append({
                "category": cat,
                "domain": dom,
                "real_ip": real_ip,
                "isp_tls": isp_tls,
                "isp_https": isp_https,
                "isp_http": isp_http,
            })

        if progress_cb:
            progress_cb("[Stage 2/6 DPI] Running dual-server synthetic SNI trap...")
        synthetic_dual = []
        for sni in SYNTHETIC_SNI_DOMAINS:
            isp_hetzner = raw_tls_probe(hetzner_ip, sni, source_ip=src_ip, mode="normal", timeout=3.0)
            isp_vultr = raw_tls_probe(vultr_ip, sni, source_ip=src_ip, mode="normal", timeout=3.0)
            isp_http_hetzner = http_host_probe(hetzner_ip, sni, source_ip=src_ip, timeout=2.5)
            synthetic_dual.append({
                "synthetic_sni": sni,
                "isp_hetzner": isp_hetzner,
                "isp_vultr": isp_vultr,
                "isp_http_host_hetzner": isp_http_hetzner,
            })

        if progress_cb:
            progress_cb("[Stage 2/6 DPI] Running 9-shape TLS parser evasion matrix...")
        evasion_matrix = []
        for host, ip in EVASION_TARGETS:
            row = {"host": host, "ip": ip, "modes": {}}
            for m in evasion_modes:
                row["modes"][m] = raw_tls_probe(ip, host, source_ip=src_ip, mode=m, timeout=3.5)
            evasion_matrix.append(row)

    return {
        "domain_dpi": domain_dpi,
        "synthetic_sni_probes": synthetic_dual,
        "evasion_matrix": evasion_matrix,
    }


def run_control_phase(isp_state, has_control=True, progress_cb=None):
    hetzner_ip = SYNTHETIC_CONTROLS[0][1]
    domain_dpi = []
    items = isp_state["domain_dpi"]
    for idx, d in enumerate(items):
        if progress_cb and has_control and idx % 25 == 0:
            progress_cb(f"[Stage 2/6 DPI Control] Verifying {idx + 1}/{len(items)}...")
        if has_control:
            ctl_tls = raw_tls_probe(d["real_ip"], d["domain"], source_ip=None, mode="normal", timeout=3.0)
            ctl_https = https_status_probe(d["real_ip"], d["domain"], source_ip=None, timeout=3.5) if ctl_tls["ok"] else None
        else:
            ctl_tls = None
            ctl_https = None
        domain_dpi.append({
            "category": d["category"],
            "domain": d["domain"],
            "real_ip": d["real_ip"],
            "isp_tls": d["isp_tls"],
            "control_tls": ctl_tls,
            "isp_https": d["isp_https"],
            "control_https": ctl_https,
            "isp_http": d["isp_http"],
        })

    synthetic_dual = []
    for s in isp_state["synthetic_sni_probes"]:
        ctl_hetzner = raw_tls_probe(hetzner_ip, s["synthetic_sni"], source_ip=None, mode="normal", timeout=3.0) if has_control else None
        synthetic_dual.append({
            "synthetic_sni": s["synthetic_sni"],
            "isp_hetzner": s["isp_hetzner"],
            "control_hetzner": ctl_hetzner,
            "isp_vultr": s["isp_vultr"],
            "isp_http_host_hetzner": s["isp_http_host_hetzner"],
        })

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "has_control": has_control,
        "domain_dpi_count": len(domain_dpi),
        "domain_dpi": domain_dpi,
        "synthetic_sni_probes": synthetic_dual,
        "evasion_matrix": isp_state["evasion_matrix"],
    }


def save_outputs(raw_dir, data):
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "02_deep_dpi_forensics.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    with (raw_dir / "02_dpi_matrix.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "domain", "real_ip", "isp_tls_outcome", "isp_tls_ms", "control_tls_outcome", "isp_https_status", "control_https_status", "isp_http_sig"])
        for d in data["domain_dpi"]:
            w.writerow([
                d["category"],
                d["domain"],
                d["real_ip"],
                d["isp_tls"]["outcome"],
                d["isp_tls"]["tls_ms"],
                (d.get("control_tls") or {}).get("outcome", ""),
                (d.get("isp_https") or {}).get("status", ""),
                (d.get("control_https") or {}).get("status", ""),
                d["isp_http"]["block_sig"] or d["isp_http"]["status"] or d["isp_http"]["error"],
            ])

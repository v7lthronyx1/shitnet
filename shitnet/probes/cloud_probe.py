import concurrent.futures
import csv
import json
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from ..targets import FALLBACK_DOMAIN_IPS, MTR_DEFAULT_TARGETS, PINNED_CLOUD_ENDPOINTS
from . import capture_pcap, resolve_control_host


def tcp_tls_probe(ip, sni, source_ip=None, timeout=4.2):
    out = {"tcp_ok": False, "tls_ok": False, "tcp_ms": None, "tls_ms": None, "error": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if source_ip:
            s.bind((source_ip, 0))
        t0 = time.monotonic()
        s.connect((ip, 443))
        out["tcp_ok"] = True
        out["tcp_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        t1 = time.monotonic()
        ws = ctx.wrap_socket(s, server_hostname=sni)
        out["tls_ok"] = True
        out["tls_ms"] = round((time.monotonic() - t1) * 1000.0, 2)
        ws.close()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        if s:
            try:
                s.close()
            except Exception:
                pass
    return out


def ping_loss(ip, source_ip=None, count=3):
    cmd = ["ping", "-n", "-c", str(count), "-W", "2"]
    if source_ip:
        cmd += ["-I", source_ip]
    cmd.append(ip)
    p = subprocess.run(cmd, capture_output=True, text=True)
    loss = 100.0
    avg_ms = None
    m_loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", p.stdout)
    if m_loss:
        loss = float(m_loss.group(1))
    m_rtt = re.search(r"min/avg/max/(?:mdev|stddev)\s*=\s*([\d.]+)/([\d.]+)/", p.stdout)
    if m_rtt:
        avg_ms = float(m_rtt.group(2))
    return {"loss_pct": loss, "avg_ms": avg_ms}


def run_mtr(ip, source_ip=None, tcp=False, count=5):
    cmd = ["mtr", "-rn"]
    if source_ip:
        cmd += ["-a", source_ip]
    cmd += ["-c", str(count)]
    if tcp:
        cmd += ["-T", "-P", "443"]
    cmd.append(ip)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
    return p.stdout


def parse_mtr_hops(mtr_text):
    hops = []
    for line in str(mtr_text or "").splitlines():
        m = re.match(r"^\s*(\d+)\.\|--\s+(\S+)\s+(\d+(?:\.\d+)?)%\s+\d+\s+[\d.]+\s+([\d.]+)\s+[\d.]+\s+([\d.]+)", line)
        if m:
            hops.append({
                "hop": int(m.group(1)),
                "host": m.group(2),
                "loss_pct": float(m.group(3)),
                "avg_ms": float(m.group(4)),
                "worst_ms": float(m.group(5)),
            })
    return hops


def detect_mtr_loop_summary(mtr_traces):
    summaries = []
    for tr in mtr_traces:
        raw_text = tr.get("icmp") or tr.get("tcp443") or ""
        hops = parse_mtr_hops(raw_text)
        if not hops:
            continue
        max_hop = hops[-1]["hop"]
        last_host = hops[-1]["host"]
        priv_loop_ips = []
        seen = {}
        for h in hops:
            ip = h["host"]
            if ip.startswith(("10.", "100.64.", "172.16.", "192.168.")):
                seen[ip] = seen.get(ip, 0) + 1
                if seen[ip] >= 2 and ip not in priv_loop_ips:
                    priv_loop_ips.append(ip)
        final_loss = hops[-1]["loss_pct"]
        worst_ms = max(h["worst_ms"] for h in hops)
        reached = (last_host == tr["ip"] and final_loss < 100.0)
        has_loop = (max_hop >= 28 and not reached) or len(priv_loop_ips) > 0
        summaries.append({
            "label": tr["label"],
            "ip": tr["ip"],
            "max_hop": max_hop,
            "reached": reached,
            "has_loop": has_loop,
            "loop_ips": priv_loop_ips,
            "last_loss_pct": final_loss,
            "worst_ms": round(worst_ms, 1),
        })
    return summaries


def classify_cloud(isp, ctl):
    if ctl is not None and not ctl["tcp_ok"]:
        return "VPN_UNREACHABLE"
    if isp["tcp_ok"] and isp["tls_ok"]:
        return "OK_BOTH" if ctl is not None else "OK_DIRECT"
    if isp["tcp_ok"] and not isp["tls_ok"]:
        err = (isp["error"] or "").lower()
        if "reset" in err or "eof" in err:
            return "ISP_DPI_TLS_RST"
        return "ISP_TLS_DISRUPTED"
    err = (isp["error"] or "").lower()
    if "113" in err or "no route" in err:
        return "ISP_CORE_ROUTING_LOOP"
    if "reset" in err:
        return "ISP_TCP_RST_BLOCKED"
    return "ISP_L3_L4_BLACKHOLE"


def run_isp_phase(pcap_dir, isp_iface, src_ip, control_dns=None, can_resolve_control=False, dns_resolved_map=None, progress_cb=None):
    pcap_path = pcap_dir / "03_cloud_infra.pcapng"
    resolved_cache = dict(dns_resolved_map or {})

    with capture_pcap(isp_iface, pcap_path, snaplen=512, progress_cb=progress_cb):
        isp_results = []
        mtr_targets = set(MTR_DEFAULT_TARGETS)
        for idx, (prov, label, fixed_ip, sni) in enumerate(PINNED_CLOUD_ENDPOINTS):
            if progress_cb and idx % 15 == 0:
                progress_cb(f"[Stage 3/6 Cloud] Probing {idx + 1}/{len(PINNED_CLOUD_ENDPOINTS)} ({label})...")
            ip = fixed_ip
            if not ip:
                if sni in resolved_cache and resolved_cache[sni]:
                    ip = resolved_cache[sni][0]
                elif can_resolve_control:
                    ips = resolve_control_host(sni, control_dns=control_dns or "1.1.1.1")
                    if ips:
                        ip = ips[0]
                if not ip and sni in FALLBACK_DOMAIN_IPS:
                    ip = FALLBACK_DOMAIN_IPS[sni][0]
            if not ip:
                continue
            isp = tcp_tls_probe(ip, sni, source_ip=src_ip, timeout=4.0)
            isp_ping = ping_loss(ip, source_ip=src_ip, count=3)
            if not isp["tls_ok"] and len(mtr_targets) < 20:
                mtr_targets.add((label, ip))
            isp_results.append({
                "provider": prov,
                "host": label,
                "sni": sni,
                "ip": ip,
                "isp": isp,
                "isp_ping": isp_ping,
            })

        if progress_cb:
            progress_cb(f"[Stage 3/6 Cloud] Running parallel ICMP + TCP443 MTR traces ({len(mtr_targets)} targets)...")
        mtr_traces = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futs = {}
            for label, ip in sorted(mtr_targets):
                futs[ex.submit(run_mtr, ip, src_ip, False, 5)] = (label, ip, "icmp")
                futs[ex.submit(run_mtr, ip, src_ip, True, 5)] = (label, ip, "tcp443")
            grouped = {}
            for fut in concurrent.futures.as_completed(futs):
                label, ip, mode = futs[fut]
                key = (label, ip)
                grouped.setdefault(key, {"label": label, "ip": ip})
                try:
                    grouped[key][mode] = fut.result()
                except Exception as e:
                    grouped[key][mode] = f"ERROR: {e}"
            mtr_traces = list(grouped.values())

    return {
        "isp_endpoints": isp_results,
        "mtr_traces": mtr_traces,
    }


def run_control_phase(isp_state, has_control=True, progress_cb=None):
    results = []
    items = isp_state["isp_endpoints"]
    for idx, row in enumerate(items):
        if progress_cb and has_control and idx % 15 == 0:
            progress_cb(f"[Stage 3/6 Cloud Control] Verifying {idx + 1}/{len(items)}...")
        if has_control:
            ctl = tcp_tls_probe(row["ip"], row["sni"], source_ip=None, timeout=4.2)
            ctl_ping = ping_loss(row["ip"], source_ip=None, count=3)
        else:
            ctl = None
            ctl_ping = None
        status = classify_cloud(row["isp"], ctl)
        results.append({
            "provider": row["provider"],
            "host": row["host"],
            "sni": row["sni"],
            "ip": row["ip"],
            "status": status,
            "isp": row["isp"],
            "control": ctl,
            "isp_ping": row["isp_ping"],
            "control_ping": ctl_ping,
        })

    mtr_summary = detect_mtr_loop_summary(isp_state["mtr_traces"])
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "has_control": has_control,
        "endpoints_count": len(results),
        "endpoints": results,
        "mtr_traces": isp_state["mtr_traces"],
        "mtr_loop_summary": mtr_summary,
    }


def save_outputs(raw_dir, data):
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "03_cloud_infra_forensics.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    with (raw_dir / "03_cloud_matrix.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["provider", "host", "ip", "status", "isp_tcp_ok", "isp_tls_ok", "isp_tcp_ms", "isp_icmp_loss", "isp_err", "control_tcp_ok", "control_tls_ok", "control_tcp_ms"])
        for r in data["endpoints"]:
            ctl = r.get("control") or {}
            w.writerow([
                r["provider"],
                r["host"],
                r["ip"],
                r["status"],
                r["isp"]["tcp_ok"],
                r["isp"]["tls_ok"],
                r["isp"]["tcp_ms"],
                r["isp_ping"]["loss_pct"],
                r["isp"]["error"] or "",
                ctl.get("tcp_ok", ""),
                ctl.get("tls_ok", ""),
                ctl.get("tcp_ms", ""),
            ])

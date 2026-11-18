import json
import shutil
import statistics
import subprocess
from scipy import stats
from ..netenv import is_private_or_reserved


def run_tshark(pcap_path, display_filter, fields):
    if not shutil.which("tshark") or not pcap_path.exists() or pcap_path.stat().st_size < 64:
        return []
    cmd = ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "fields"]
    for fld in fields:
        cmd += ["-e", fld]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        return []
    return [line.split("\t") for line in p.stdout.splitlines()]


def analyze_dns_pcap(pcap_path, client_ip, gw_ip):
    if not pcap_path.exists():
        return {"forged_count": 0, "clean_count": 0, "forged_ttls": [], "clean_ttls": [], "forged_median_rtt_ms": None, "clean_median_rtt_ms": None, "forged_samples": [], "clean_samples": []}
    rows = run_tshark(
        pcap_path,
        "dns",
        ["frame.time_relative", "ip.src", "ip.dst", "ip.ttl", "udp.srcport", "tcp.srcport", "dns.id", "dns.flags.response", "dns.qry.name", "dns.a"],
    )
    queries = {}
    forged = []
    clean = []
    for r in rows:
        while len(r) < 10:
            r.append("")
        t, src, dst, ttl, usrc, tsrc, did, is_resp, qname, ans_ips = r[:10]
        if not t or not did or not src or not dst:
            continue
        if src == gw_ip or dst == gw_ip:
            pass
        ts = float(t)
        ttl_i = int(ttl) if ttl.isdigit() else None
        if src == client_ip and is_resp in ("0", "False", ""):
            queries[(dst, did, qname)] = ts
        elif dst == client_ip and is_resp in ("1", "True"):
            t0 = queries.get((src, did, qname))
            rtt = round((ts - t0) * 1000.0, 2) if t0 is not None else None
            proto = "TCP" if tsrc else "UDP"
            port = tsrc or usrc
            ans_list = [x.strip() for x in ans_ips.split(",") if x.strip()]
            is_known_hijack = any(x in ("10.10.34.34", "10.10.34.35", "10.10.34.36", "216.239.38.120") for x in ans_list)
            is_external_rfc1918 = (src != gw_ip) and any(is_private_or_reserved(x) for x in ans_list)
            is_ext_resolver = src not in (gw_ip, "178.22.122.100", "185.51.200.2")
            rec = {"resolver": src, "proto": proto, "port": port, "qname": qname, "ans": ans_ips, "ttl": ttl_i, "rtt_ms": rtt}
            if is_ext_resolver and (is_known_hijack or is_external_rfc1918):
                forged.append(rec)
            elif is_ext_resolver and ans_ips:
                clean.append(rec)

    return {
        "forged_count": len(forged),
        "clean_count": len(clean),
        "forged_ttls": sorted(set(x["ttl"] for x in forged if x["ttl"] is not None)),
        "clean_ttls": sorted(set(x["ttl"] for x in clean if x["ttl"] is not None)),
        "forged_median_rtt_ms": round(statistics.median([x["rtt_ms"] for x in forged if x["rtt_ms"] is not None]), 2) if forged else None,
        "clean_median_rtt_ms": round(statistics.median([x["rtt_ms"] for x in clean if x["rtt_ms"] is not None]), 2) if clean else None,
        "forged_samples": forged[:30],
        "clean_samples": clean[:20],
    }


def analyze_dpi_pcaps(pcap_dir, pcap_names, client_ip):
    all_events = []
    for pname in pcap_names:
        p = pcap_dir / pname
        if not p.exists():
            continue
        rows = run_tshark(
            p,
            "tcp.flags.syn==1 || tcp.flags.reset==1 || tls.handshake.type==1",
            [
                "tcp.stream",
                "frame.time_relative",
                "ip.src",
                "ip.dst",
                "ip.ttl",
                "ip.id",
                "tcp.srcport",
                "tcp.dstport",
                "tcp.flags.syn",
                "tcp.flags.ack",
                "tcp.flags.reset",
                "tcp.window_size_value",
                "tls.handshake.type",
                "tls.handshake.extensions_server_name",
            ],
        )
        streams = {}
        for r in rows:
            while len(r) < 14:
                r.append("")
            sid, t, src, dst, ttl, ipid, sp, dp, syn, ack, rst, win, htype, sni = r[:14]
            if not sid:
                continue
            st = streams.setdefault(sid, {"syn_t": None, "synack_t": None, "synack_ttl": None, "ch_t": None, "sni": "", "remote_ip": "", "remote_port": "", "rsts": []})
            ts = float(t)
            if syn in ("1", "True") and ack in ("0", "False", "") and src == client_ip:
                st["syn_t"] = ts
                st["remote_ip"] = dst
                st["remote_port"] = dp
            elif syn in ("1", "True") and ack in ("1", "True") and dst == client_ip:
                st["synack_t"] = ts
                st["synack_ttl"] = int(ttl) if ttl.isdigit() else None
            elif htype == "1" and src == client_ip:
                st["ch_t"] = ts
                if sni:
                    st["sni"] = sni
            elif rst in ("1", "True") and dst == client_ip:
                st["rsts"].append({
                    "t": ts,
                    "ttl": int(ttl) if ttl.isdigit() else None,
                    "ip_id": ipid,
                    "win": int(win) if win.isdigit() else None,
                })
        for _, st in streams.items():
            if st["syn_t"] is None or st["synack_t"] is None or st["ch_t"] is None or not st["rsts"]:
                continue
            srv_rtt = round((st["synack_t"] - st["syn_t"]) * 1000.0, 2)
            first_rst = st["rsts"][0]
            rst_delay = round((first_rst["t"] - st["ch_t"]) * 1000.0, 2)
            if rst_delay < 0 or srv_rtt <= 0:
                continue
            ttl_mismatch = (first_rst["ttl"] != st["synack_ttl"])
            early_rst = rst_delay < (0.85 * srv_rtt)
            all_events.append({
                "pcap": pname,
                "remote_ip": st["remote_ip"],
                "remote_port": st["remote_port"],
                "sni": st["sni"],
                "server_synack_ttl": st["synack_ttl"],
                "server_rtt_ms": srv_rtt,
                "rst_ttl": first_rst["ttl"],
                "rst_ip_id": first_rst["ip_id"],
                "rst_win": first_rst["win"],
                "rst_after_ch_ms": rst_delay,
                "ttl_mismatch": ttl_mismatch,
                "early_rst": early_rst,
            })

    rtts = [e["server_rtt_ms"] for e in all_events]
    rsts = [e["rst_after_ch_ms"] for e in all_events]
    ttl_counts = {}
    for e in all_events:
        k = str(e["rst_ttl"])
        ttl_counts[k] = ttl_counts.get(k, 0) + 1
    top_ttl = None
    top_ttl_count = 0
    if ttl_counts:
        top_k = max(ttl_counts.keys(), key=lambda x: ttl_counts[x])
        if top_k != "None":
            top_ttl = int(top_k)
            top_ttl_count = ttl_counts[top_k]

    p_val = None
    if len(rtts) >= 3 and len(rsts) >= 3:
        _, p_val = stats.mannwhitneyu(rsts, rtts, alternative="less")

    return {
        "n_events": len(all_events),
        "dominant_rst_ttl": top_ttl,
        "n_dominant_ttl": top_ttl_count,
        "n_ttl_60": sum(1 for e in all_events if e["rst_ttl"] == 60),
        "n_ttl_mismatch": sum(1 for e in all_events if e["ttl_mismatch"]),
        "n_cloned_ttl_early": sum(1 for e in all_events if (not e["ttl_mismatch"]) and e["early_rst"]),
        "n_early_rst": sum(1 for e in all_events if e["early_rst"]),
        "rst_ttl_dist": ttl_counts,
        "median_server_rtt_ms": round(statistics.median(rtts), 2) if rtts else None,
        "median_rst_delay_ms": round(statistics.median(rsts), 2) if rsts else None,
        "min_rst_delay_ms": min(rsts) if rsts else None,
        "max_rst_delay_ms": max(rsts) if rsts else None,
        "mannwhitney_u_less_pvalue": float(p_val) if p_val is not None else None,
        "sample_events": all_events[:80],
        "all_events": all_events,
    }


def analyze_http_blockpages(pcap_path):
    if not pcap_path.exists():
        return []
    rows = run_tshark(
        pcap_path,
        "http.response.code==403 || http.response.code==599",
        ["frame.number", "ip.src", "ip.ttl", "http.response.code", "http.server"],
    )
    return [{"frame": r[0], "ip": r[1], "ttl": r[2], "code": r[3], "server": r[4] if len(r) > 4 else ""} for r in rows]


def analyze_quic_pcap(pcap_path, client_ip):
    if not pcap_path.exists():
        return {"udp_443_outbound_pkts": 0, "udp_443_inbound_replies": 0}
    rows = run_tshark(
        pcap_path,
        "udp.port==443",
        ["ip.src", "ip.dst", "udp.length"],
    )
    out_pkts = sum(1 for r in rows if r[0] == client_ip)
    in_pkts = sum(1 for r in rows if len(r) > 1 and r[1] == client_ip)
    return {"udp_443_outbound_pkts": out_pkts, "udp_443_inbound_replies": in_pkts}


def analyze_fastly_tcp_pcap(pcap_path, target_ip="151.101.18.132"):
    if not pcap_path.exists():
        return {"n_streams": 0, "server_retransmissions": 0, "sample_streams": []}
    rows = run_tshark(
        pcap_path,
        f"ip.addr=={target_ip}",
        ["tcp.stream", "ip.src", "tcp.len", "tcp.seq", "tcp.analysis.retransmission"],
    )
    streams = {}
    retrans = 0
    for r in rows:
        while len(r) < 5:
            r.append("")
        sid, src, tlen, seq, rt = r[:5]
        if not sid:
            continue
        st = streams.setdefault(sid, {"rx_bytes": 0, "max_seq": 0})
        if src == target_ip:
            st["rx_bytes"] += int(tlen) if tlen.isdigit() else 0
            st["max_seq"] = max(st["max_seq"], int(seq) if seq.isdigit() else 0)
            if rt:
                retrans += 1
    return {"n_streams": len(streams), "server_retransmissions": retrans, "sample_streams": list(streams.items())[:15]}


def run_forensics(pcap_dir, raw_dir, client_ip, gw_ip, progress_cb=None):
    if progress_cb:
        progress_cb("[Stage 6/6 Forensics] Analyzing PCAP captures with tshark...")
    dns_stats = analyze_dns_pcap(pcap_dir / "01_dns_forensics.pcapng", client_ip, gw_ip)
    dpi_stats = analyze_dpi_pcaps(pcap_dir, ["02_dpi_forensics.pcapng", "03_cloud_infra.pcapng", "04_protocols.pcapng"], client_ip)
    http_403 = analyze_http_blockpages(pcap_dir / "02_dpi_forensics.pcapng")
    quic_stats = analyze_quic_pcap(pcap_dir / "04_protocols.pcapng", client_ip)
    fastly_stats = analyze_fastly_tcp_pcap(pcap_dir / "05_speed_thresholds.pcapng")

    summary = {
        "dns_pcap_hijack_proof": dns_stats,
        "dpi_rst_timing_ttl_proof": {k: v for k, v in dpi_stats.items() if k != "all_events"},
        "http_block_or_403_frames": http_403[:40],
        "quic_udp443_packet_balance": quic_stats,
        "fastly_tcp_stats": fastly_stats,
    }
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "06_pcap_deep_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (raw_dir / "06_pcap_all_rst_events.json").write_text(json.dumps(dpi_stats["all_events"], indent=2, ensure_ascii=False), encoding="utf-8")
    return summary, dpi_stats["all_events"]

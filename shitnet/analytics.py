import json
import pathlib
from .netenv import is_private_or_reserved


def load_json_if(path):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return None


def fmt_pval(pval):
    if pval is None:
        return "N/A"
    return f"{pval:.2e}"


def fmt_num(val, suffix="", default="N/A"):
    if val is None:
        return default
    return f"{val}{suffix}"


def _cloud_provider_empty():
    return {
        "OK_BOTH": 0,
        "OK_DIRECT": 0,
        "ISP_L3_L4_BLACKHOLE": 0,
        "ISP_DPI_TLS_RST": 0,
        "ISP_TLS_DISRUPTED": 0,
        "ISP_CORE_ROUTING_LOOP": 0,
        "ISP_TCP_RST_BLOCKED": 0,
        "VPN_UNREACHABLE": 0,
    }


def _detect_fastly_stall(d5):
    rows = [f for f in d5.get("fastly_thresholds", []) if f["ip"] == "151.101.18.132" and f["scheme"] == "http"]
    full_rows = [f for f in rows if f["range"] == "FULL"]
    if not full_rows:
        return {"stalled": False, "stall_bytes": None, "mbps": None}
    fr = full_rows[0]["isp"]
    if fr["rc"] != 0 or fr["bytes"] < 50000:
        return {"stalled": True, "stall_bytes": fr["bytes"], "mbps": fr["mbps"]}
    return {"stalled": False, "stall_bytes": fr["bytes"], "mbps": fr["mbps"]}


def _load_compare_runs(compare_dirs):
    history = []
    for raw_p in compare_dirs or []:
        p = pathlib.Path(raw_p).expanduser().resolve()
        cand = p
        if not p.is_file():
            for rel in (
                pathlib.Path("raw_data/07_aggregated_metrics.json"),
                pathlib.Path("evidence/raw_data/07_aggregated_metrics.json"),
                pathlib.Path("raw_data/06_aggregated_metrics.json"),
                pathlib.Path("evidence/raw_data/06_aggregated_metrics.json"),
            ):
                if (p / rel).exists():
                    cand = p / rel
                    break
        if not cand.exists() or not cand.is_file():
            continue
        prev = json.loads(cand.read_text(encoding="utf-8"))
        if "pcap_dpi_timing_ttl" in prev:
            timing = prev.get("pcap_dpi_timing_ttl", {})
            n_ev = timing.get("n_events", 0)
            n_low = timing.get("n_low_ttl_60", 0)
            dom_share = round(100.0 * n_low / n_ev, 1) if n_ev else 0.0
            prov = prev.get("cloud_provider_breakdown", {})
            total_c = sum(sum(v.values()) for v in prov.values())
            ok_c = sum(v.get("ok", 0) for v in prov.values())
            dis_c = max(0, total_c - ok_c)
            mech = prev.get("mechanisms", {})
            history.append({
                "label": "2026-11-13 (V1 Baseline)",
                "timestamp": "2026-11-13T08:25:24+00:00",
                "ip": "5.213.x.x",
                "rst_events": n_ev,
                "cloud_fail_pct": round(100.0 * dis_c / max(1, total_c), 1),
                "cloud_fail_count": dis_c,
                "cloud_total": max(1, total_c),
                "dns_sinkholes": mech.get("DNS Sinkhole (10.10.34.36)", 0),
                "dominant_ttl_share_pct": dom_share,
                "median_rst_ms": timing.get("median_rst_delay_ms"),
            })
            continue
        meta = prev.get("session_meta", {})
        rst = prev.get("pcap_dpi_rst", {})
        cld = prev.get("cloud_summary", {})
        dns = prev.get("dns_summary", {})
        total_c = max(1, cld.get("total_endpoints", 1))
        dis_c = cld.get("isp_disrupted", cld.get("mci_disrupted", 0))
        n_ev = rst.get("n_events", 0)
        dom_n = rst.get("n_dominant_ttl", rst.get("n_ttl_60", 0))
        dom_share = round(100.0 * dom_n / n_ev, 1) if n_ev else 0.0
        history.append({
            "label": f"{meta.get('timestamp_utc', '')[:10]} ({meta.get('connection_type', meta.get('interface', 'Run'))})",
            "timestamp": meta.get("timestamp_utc", ""),
            "ip": meta.get("isp_public_ip", meta.get("mci_public_ip", "")),
            "rst_events": n_ev,
            "cloud_fail_pct": round(100.0 * dis_c / total_c, 1),
            "cloud_fail_count": dis_c,
            "cloud_total": total_c,
            "dns_sinkholes": dns.get("sinkhole_10_10_34_x", 0),
            "dominant_ttl_share_pct": dom_share,
            "median_rst_ms": rst.get("median_rst_delay_ms"),
        })
    return history


def compute_aggregated(d1, d2, d3, d4, d5, d6, rsts, mode="dual", compare_dirs=None):
    net = d1["network_identity"]
    has_control = bool(d1.get("has_control", True))
    op = net.get("operator") or {}
    gw_ip = net.get("gw_ip", "")

    cat_stats = {}
    dpi_by_dom = {r["domain"]: r for r in d2.get("domain_dpi", [])}
    for r in d1.get("domains", []):
        cat = r["category"]
        dom = r["domain"]
        cat_stats.setdefault(cat, {
            "total_dns": 0,
            "total_dpi": 0,
            "dns_sinkhole": 0,
            "dns_safesearch": 0,
            "dns_rfc1918": 0,
            "dns_nxdomain": 0,
            "sni_rst": 0,
            "tcp_tls_timeout": 0,
        })
        cat_stats[cat]["total_dns"] += 1
        v = r["verdict_gw"]
        if v == "SINKHOLE_10_10_34_X":
            cat_stats[cat]["dns_sinkhole"] += 1
        elif v == "FORCED_SAFESEARCH":
            cat_stats[cat]["dns_safesearch"] += 1
        elif v == "PRIVATE_RFC1918_REDIRECT":
            cat_stats[cat]["dns_rfc1918"] += 1
        elif v == "NXDOMAIN_BLOCK":
            cat_stats[cat]["dns_nxdomain"] += 1

        dr = dpi_by_dom.get(dom)
        if dr:
            cat_stats[cat]["total_dpi"] += 1
            out = dr["isp_tls"]["outcome"]
            if out == "TCP_RST_INJECTED":
                cat_stats[cat]["sni_rst"] += 1
            elif out in ("TCP_TIMEOUT", "TLS_TIMEOUT"):
                cat_stats[cat]["tcp_tls_timeout"] += 1

    ext_resolvers_tested = 0
    ext_resolvers_hijacked = 0
    ext_resolvers_timeout = 0
    ext_resolvers_eperm = 0
    port_5353_hijacked = 0
    skip_srvs = {gw_ip, "178.22.122.100", "185.51.200.2"}
    for rp in d1.get("resolver_probes", []):
        srv = rp["server"]
        if srv in skip_srvs:
            continue
        ext_resolvers_tested += 1
        x_res = rp["results"].get("x.com", {})
        ips = x_res.get("ips") or []
        is_hijack = x_res.get("ok") and (
            any(ip.startswith("10.10.34.") for ip in ips)
            or any(is_private_or_reserved(ip) for ip in ips)
        )
        if is_hijack:
            ext_resolvers_hijacked += 1
            if rp.get("port") == 5353:
                port_5353_hijacked += 1
        elif str(x_res.get("error", "")).startswith("HOST_SOCKET_EPERM"):
            ext_resolvers_eperm += 1
        else:
            ext_resolvers_timeout += 1

    https_rr_ctl = sum(1 for r in d1.get("domains", []) if r.get("control_https_count", 0) > 0)
    https_rr_isp = sum(
        1 for r in d1.get("domains", [])
        if (r.get("isp_gw_https") or {}).get("ips")
        or (r.get("isp_gw_https") or {}).get("other")
        or (r.get("isp_gw_https") or {}).get("cnames")
    )
    dnssec_ctl = sum(1 for r in d1.get("domains", []) if (r.get("control_dnssec") or {}).get("has_rrsig") or (r.get("control_dnssec") or {}).get("ad"))
    dnssec_isp = sum(1 for r in d1.get("domains", []) if (r.get("isp_dnssec") or {}).get("has_rrsig") or (r.get("isp_dnssec") or {}).get("ad"))

    sni_rst_doms = [x["domain"] for x in d2.get("domain_dpi", []) if x["isp_tls"]["outcome"] == "TCP_RST_INJECTED"]
    tmo_doms = [x["domain"] for x in d2.get("domain_dpi", []) if x["isp_tls"]["outcome"] in ("TCP_TIMEOUT", "TLS_TIMEOUT")]
    tls_ok_items = [x for x in d2.get("domain_dpi", []) if x["isp_tls"]["outcome"] == "TLS_SERVER_HELLO"]
    geo_both_403 = [
        x["domain"] for x in tls_ok_items
        if ((x.get("isp_https") or {}).get("status") in (403, 421))
        and ((x.get("control_https") or {}).get("status") in (403, 421))
    ]
    geo_isp_only_403 = [
        x["domain"] for x in tls_ok_items
        if ((x.get("isp_https") or {}).get("status") in (403, 421))
        and (
            (not has_control)
            or ((x.get("control_https") or {}).get("status") not in (403, 421, None))
        )
    ]
    clean_200_count = len(tls_ok_items) - len(geo_both_403) - len(geo_isp_only_403)

    synth_list = d2.get("synthetic_sni_probes", [])
    synth_hetzner_rst = sum(1 for s in synth_list if s["isp_hetzner"]["outcome"] == "TCP_RST_INJECTED")
    synth_vultr_rst = sum(1 for s in synth_list if s["isp_vultr"]["outcome"] == "TCP_RST_INJECTED")
    synth_http_blk = sum(1 for s in synth_list if (s.get("isp_http_host_hetzner") or {}).get("block_sig") == "ISP_HTTP_BLOCKPAGE_NSV2")
    synth_clean_both = sum(1 for s in synth_list if s["isp_hetzner"]["outcome"] == "TLS_SERVER_HELLO" and s["isp_vultr"]["outcome"] == "TLS_SERVER_HELLO")
    blocked_synth_names = [s["synthetic_sni"].replace("probe-test-404.", "") for s in synth_list if s["isp_hetzner"]["outcome"] == "TCP_RST_INJECTED" and s["isp_vultr"]["outcome"] == "TCP_RST_INJECTED"]
    clean_synth_names = [s["synthetic_sni"].replace("probe-test-404.", "") for s in synth_list if s["isp_hetzner"]["outcome"] == "TLS_SERVER_HELLO" and s["isp_vultr"]["outcome"] == "TLS_SERVER_HELLO"]

    evasion_modes = ["normal", "tls12", "pad1800", "ech_grease", "split_5b", "split_midsni", "split_2b", "rec_split_2", "rec_split_5"]
    evasion_summary = {}
    for m in evasion_modes:
        evasion_summary[m] = {
            "rst": sum(1 for e in d2.get("evasion_matrix", []) if e["modes"][m]["outcome"] == "TCP_RST_INJECTED"),
            "hello": sum(1 for e in d2.get("evasion_matrix", []) if e["modes"][m]["outcome"] == "TLS_SERVER_HELLO"),
            "alert": sum(1 for e in d2.get("evasion_matrix", []) if str(e["modes"][m]["outcome"]).startswith("TLS_ALERT")),
            "timeout": sum(1 for e in d2.get("evasion_matrix", []) if "TIMEOUT" in str(e["modes"][m]["outcome"])),
        }
    split_2b_bypass_hosts = [
        e["host"] for e in d2.get("evasion_matrix", [])
        if e["modes"]["normal"]["outcome"] == "TCP_RST_INJECTED"
        and e["modes"]["split_2b"]["outcome"] == "TLS_SERVER_HELLO"
    ]

    cloud_status = {}
    cloud_by_provider = {}
    ctl_tcp_ok = 0
    for ep in d3.get("endpoints", []):
        st = ep["status"]
        prov = ep["provider"]
        cloud_status[st] = cloud_status.get(st, 0) + 1
        if (ep.get("control") or {}).get("tcp_ok"):
            ctl_tcp_ok += 1
        p = cloud_by_provider.setdefault(prov, _cloud_provider_empty())
        p[st] = p.get(st, 0) + 1
    total_eps = len(d3.get("endpoints", []))
    isp_cloud_ok = cloud_status.get("OK_BOTH", 0) + cloud_status.get("OK_DIRECT", 0)
    isp_disrupted = max(0, total_eps - isp_cloud_ok - cloud_status.get("VPN_UNREACHABLE", 0))
    disrupted_pct = round(100.0 * isp_disrupted / total_eps, 1) if total_eps else 0.0

    dot_intl = [r for r in d4.get("dot", []) if r["label"] not in ("Shecan", "Control-Port853-EC2")]
    dot_isp_ok = sum(1 for r in dot_intl if r["isp"]["dns_ok"])
    dot_ctl_ok = sum(1 for r in dot_intl if (r.get("control") or {}).get("dns_ok"))

    doh_domains = [r for r in d4.get("doh", []) if r["label"].endswith("-Domain") and not r["label"].startswith("Shecan")]
    doh_isp_ok = sum(1 for r in doh_domains if r["isp"].get("ok"))
    doh_ctl_ok = sum(1 for r in doh_domains if (r.get("control") or {}).get("ok"))
    doh_isp_rst = sum(1 for r in doh_domains if not r["isp"].get("ok") and ("reset" in str(r["isp"].get("err", "")).lower() or r["isp"].get("rc") == 35))

    doq_rows = [r for r in d4.get("quic", []) if r["port"] == 853]
    doq_isp_ok = sum(1 for r in doq_rows if r["isp_aioquic"]["ok"])
    doq_ctl_ok = sum(1 for r in doq_rows if (r.get("control_aioquic") or {}).get("ok"))

    ntp_google = [r for r in d4.get("ntp", []) if r["host"] == "time.google.com"]
    ntp_google_isp_ok = bool(ntp_google and ntp_google[0]["isp"]["ok"])
    ntp_google_ctl_ok = bool(ntp_google and (ntp_google[0].get("control") or {}).get("ok"))

    stun_rows = d4.get("stun", [])
    stun_isp_ok = sum(1 for r in stun_rows if r["isp"]["ok"])
    stun_ctl_ok = sum(1 for r in stun_rows if (r.get("control") or {}).get("ok"))

    pmtu_passed = [row["wire_mtu"] for row in d4.get("pmtu_isp", []) if row["ok"]]
    pmtu_bytes = max(pmtu_passed) if pmtu_passed else None

    sp_list = d5.get("speed_benchmarks", [])
    healthy_sp = [s for s in sp_list if s["isp"]["rc"] == 0 and s["isp"]["mbps"] >= 1.0]
    max_sp_item = max(sp_list, key=lambda x: x["isp"]["mbps"]) if sp_list else None
    stalled_sp = [s for s in sp_list if s["isp"]["rc"] != 0 or s["isp"]["mbps"] < 0.5]

    jb_list = d5.get("jitter_bursts", [])
    local_jb = [j for j in jb_list if j["label"] == "Local-GW"]
    local_jitter = local_jb[0]["isp"]["stdev_ms"] if local_jb else None
    local_loss = local_jb[0]["isp"]["loss_pct"] if local_jb else None
    remote_jbs = [j for j in jb_list if j["label"] != "Local-GW" and j["isp"].get("stdev_ms") is not None]
    max_remote_jb = max(remote_jbs, key=lambda x: x["isp"]["stdev_ms"]) if remote_jbs else None

    pcap_dpi = d6.get("dpi_rst_timing_ttl_proof", {})
    n_ev = pcap_dpi.get("n_events", 0)
    dom_n = pcap_dpi.get("n_dominant_ttl", 0)
    dom_share = round(100.0 * dom_n / n_ev, 1) if n_ev else 0.0

    sinkholes_cnt = sum(v["dns_sinkhole"] for v in cat_stats.values())
    safesearch_cnt = sum(v["dns_safesearch"] for v in cat_stats.values())
    rfc1918_cnt = sum(v["dns_rfc1918"] for v in cat_stats.values())
    nxdomain_cnt = sum(v["dns_nxdomain"] for v in cat_stats.values())

    agg = {
        "session_meta": {
            "timestamp_utc": d1["timestamp_utc"],
            "mode": mode,
            "has_control": has_control,
            "isp_public_ip": net.get("isp_public_ip", ""),
            "control_public_ip": net.get("control_public_ip", ""),
            "interface": net.get("interface", ""),
            "connection_type": net.get("connection_type", ""),
            "src_ip": net.get("src_ip", ""),
            "gw_ip": gw_ip,
            "asn": net.get("asn", op.get("asn", "")),
            "prefix": net.get("prefix", ""),
            "operator": op,
        },
        "dns_summary": {
            "domains_probed": d1.get("domains_count", 0),
            "sinkhole_10_10_34_x": sinkholes_cnt,
            "forced_safesearch_216_239_38_120": safesearch_cnt,
            "private_rfc1918_redirect": rfc1918_cnt,
            "nxdomain_block": nxdomain_cnt,
            "total_dns_blocked": sinkholes_cnt + safesearch_cnt + rfc1918_cnt + nxdomain_cnt,
            "ext_resolvers_tested": ext_resolvers_tested,
            "ext_resolvers_hijacked": ext_resolvers_hijacked,
            "ext_resolvers_timeout": ext_resolvers_timeout,
            "ext_resolvers_local_eperm": ext_resolvers_eperm,
            "port_5353_hijacked": port_5353_hijacked,
            "control_https_rr": https_rr_ctl,
            "isp_https_rr": https_rr_isp,
            "control_dnssec": dnssec_ctl,
            "isp_dnssec": dnssec_isp,
        },
        "categories": cat_stats,
        "dpi_summary": {
            "domains_probed": len(d2.get("domain_dpi", [])),
            "sni_rst_count": len(sni_rst_doms),
            "tcp_tls_timeout_count": len(tmo_doms),
            "clean_200_count": max(0, clean_200_count),
            "geo_isp_only_403_hosts": geo_isp_only_403,
            "geo_both_403_hosts": geo_both_403,
            "sni_rst_hosts": sni_rst_doms,
            "timeout_hosts": tmo_doms,
        },
        "synthetic_sni": {
            "total": len(synth_list),
            "isp_hetzner_rst": synth_hetzner_rst,
            "isp_vultr_rst": synth_vultr_rst,
            "isp_http_blockpage": synth_http_blk,
            "clean_both_servers": synth_clean_both,
            "blocked_patterns": blocked_synth_names,
            "clean_patterns": clean_synth_names,
        },
        "evasion_summary": evasion_summary,
        "split_2b_bypass_hosts": split_2b_bypass_hosts,
        "pcap_dns_hijack": {k: v for k, v in d6.get("dns_pcap_hijack_proof", {}).items() if k != "forged_samples"},
        "pcap_dpi_rst": {
            **{k: v for k, v in pcap_dpi.items() if k != "sample_events"},
            "dominant_ttl_share_pct": dom_share,
        },
        "pcap_quic_udp443": d6.get("quic_udp443_packet_balance", {}),
        "pcap_fastly_tcp": {k: v for k, v in d6.get("fastly_tcp_stats", {}).items() if k != "sample_streams"},
        "fastly_stall": _detect_fastly_stall(d5),
        "cloud_summary": {
            "total_endpoints": total_eps,
            "control_tcp_ok": ctl_tcp_ok,
            "isp_disrupted": isp_disrupted,
            "disrupted_pct": disrupted_pct,
            "status_counts": cloud_status,
            "by_provider": cloud_by_provider,
            "mtr_loop_summary": d3.get("mtr_loop_summary", []),
        },
        "protocols_summary": {
            "tcp_ports_isp_ok": sum(1 for p in d4.get("tcp_ports", []) if p["isp"]["ok"]),
            "tcp_ports_ctl_ok": sum(1 for p in d4.get("tcp_ports", []) if (p.get("control") or {}).get("ok")),
            "tcp_ports_total": len(d4.get("tcp_ports", [])),
            "dot_intl_isp_ok": dot_isp_ok,
            "dot_intl_ctl_ok": dot_ctl_ok,
            "dot_intl_total": len(dot_intl),
            "doh_domain_isp_ok": doh_isp_ok,
            "doh_domain_ctl_ok": doh_ctl_ok,
            "doh_domain_isp_rst": doh_isp_rst,
            "doh_domain_total": len(doh_domains),
            "doq_853_isp_ok": doq_isp_ok,
            "doq_853_ctl_ok": doq_ctl_ok,
            "doq_853_total": len(doq_rows),
            "ntp_google_isp_ok": ntp_google_isp_ok,
            "ntp_google_ctl_ok": ntp_google_ctl_ok,
            "stun_isp_ok": stun_isp_ok,
            "stun_ctl_ok": stun_ctl_ok,
            "stun_total": len(stun_rows),
            "pmtu_isp_bytes": pmtu_bytes,
        },
        "speed_summary": {
            "max_isp_mbps": max_sp_item["isp"]["mbps"] if max_sp_item else 0.0,
            "max_isp_label": max_sp_item["label"] if max_sp_item else "",
            "healthy_count": len(healthy_sp),
            "stalled_labels": [f"{s['label']} ({s['isp']['mbps']} Mbps)" for s in stalled_sp],
            "local_gw_jitter_ms": local_jitter,
            "local_gw_loss_pct": local_loss,
            "remote_max_jitter_ms": max_remote_jb["isp"]["stdev_ms"] if max_remote_jb else None,
            "remote_max_jitter_label": max_remote_jb["label"] if max_remote_jb else "",
        },
        "speed_benchmarks": [
            {
                "label": s["label"],
                "ip": s["ip"],
                "isp_mbps": s["isp"]["mbps"],
                "isp_bytes": s["isp"]["bytes"],
                "isp_rc": s["isp"]["rc"],
                "control_mbps": (s.get("control") or {}).get("mbps"),
                "control_bytes": (s.get("control") or {}).get("bytes"),
                "control_rc": (s.get("control") or {}).get("rc"),
            }
            for s in sp_list
        ],
        "jitter_bursts": jb_list,
    }

    history = _load_compare_runs(compare_dirs)
    if history:
        history.append({
            "label": f"{agg['session_meta']['timestamp_utc'][:10]} (Current {agg['session_meta']['connection_type']})",
            "timestamp": agg["session_meta"]["timestamp_utc"],
            "ip": agg["session_meta"]["isp_public_ip"],
            "rst_events": agg["pcap_dpi_rst"].get("n_events", 0),
            "cloud_fail_pct": agg["cloud_summary"]["disrupted_pct"],
            "cloud_fail_count": agg["cloud_summary"]["isp_disrupted"],
            "cloud_total": agg["cloud_summary"]["total_endpoints"],
            "dns_sinkholes": agg["dns_summary"]["sinkhole_10_10_34_x"],
            "dominant_ttl_share_pct": agg["pcap_dpi_rst"].get("dominant_ttl_share_pct", 0.0),
            "median_rst_ms": agg["pcap_dpi_rst"].get("median_rst_delay_ms"),
        })
    agg["history_comparison"] = history
    return agg

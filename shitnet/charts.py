import matplotlib
matplotlib.use("Agg")
import matplotlib.colors as mcolors
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
from . import APP_NAME, BRAND, __version__
from .analytics import fmt_pval


def setup_mpl_style(font_size=9.5):
    plt.rcParams.update({
        "figure.facecolor": "#ffffff",
        "axes.facecolor": "#f8fafc",
        "axes.edgecolor": "#cbd5e1",
        "axes.grid": True,
        "grid.color": "#e2e8f0",
        "grid.linestyle": "--",
        "grid.linewidth": 0.7,
        "font.family": "DejaVu Sans",
        "font.size": font_size,
        "axes.titlesize": font_size + 1.5,
        "axes.titleweight": "bold",
        "axes.labelsize": font_size,
    })


def _op_tag(agg, opsec_safe=False):
    meta = agg["session_meta"]
    op = meta["operator"]
    if opsec_safe:
        return f"{op['short_en']} ({meta['asn']})"
    ip_txt = meta["isp_public_ip"] or "N/A"
    return f"{op['short_en']} ({meta['asn']} • {meta['connection_type']} • {ip_txt})"


def _brand_footer(fig):
    fig.text(
        0.99,
        0.008,
        f"{APP_NAME} v{__version__} | {BRAND}",
        ha="right",
        va="bottom",
        fontsize=7.2,
        color="#64748b",
    )


def plot_dns_layers_ax(ax1, ax2, agg, opsec_safe=False):
    cat_order = [
        ("social_video", "Social & Video"),
        ("cloud_dev_cdn", "Cloud / Dev / CDN"),
        ("linux_pkgs", "Linux / Docker / PyPI"),
        ("search_infra", "Search & Core Infra"),
        ("ai_ml_research", "AI & ML Research"),
        ("web_app_deps", "Web App / Auth / Telemetry"),
        ("domestic_ir", "Domestic IR Services"),
        ("remote_voip", "Remote Desktop & VoIP"),
        ("news_ref", "International News & Ref"),
    ]
    present = [(k, lbl) for k, lbl in cat_order if k in agg["categories"]]
    if not present:
        present = [(k, k) for k in agg["categories"]]

    labels = [f"{lbl} ({agg['categories'][k]['total_dns']})" for k, lbl in present]
    tot_dns = [agg["categories"][k]["total_dns"] for k, _ in present]
    dns_blk = [
        agg["categories"][k]["dns_sinkhole"]
        + agg["categories"][k]["dns_safesearch"]
        + agg["categories"][k]["dns_rfc1918"]
        + agg["categories"][k]["dns_nxdomain"]
        for k, _ in present
    ]
    sni_rst = [agg["categories"][k]["sni_rst"] for k, _ in present]
    tcp_tmo = [agg["categories"][k]["tcp_tls_timeout"] for k, _ in present]

    x = np.arange(len(labels))
    w = 0.2
    ds = agg["dns_summary"]
    dpi_s = agg["dpi_summary"]
    b0 = ax1.bar(x - 1.5 * w, tot_dns, w, label=f"Probed ({ds['domains_probed']})", color="#94a3b8")
    b1 = ax1.bar(x - 0.5 * w, dns_blk, w, label=f"DNS Tampered ({ds['total_dns_blocked']})", color="#d97706")
    b2 = ax1.bar(x + 0.5 * w, sni_rst, w, label=f"TLS SNI RST ({dpi_s['sni_rst_count']})", color="#dc2626")
    b3 = ax1.bar(x + 1.5 * w, tcp_tmo, w, label=f"TCP/TLS Timeout ({dpi_s['tcp_tls_timeout_count']})", color="#7c3aed")

    for bars in (b0, b1, b2, b3):
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax1.annotate(
                    f"{int(h)}",
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 2),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=7.6,
                    fontweight="bold",
                )

    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=24, ha="right", fontsize=8.3)
    ax1.set_ylabel("Domain Count")
    ax1.set_ylim(0, max(tot_dns or [1]) + 5)
    ax1.set_title(f"Multi-Layer Filtering Across {ds['domains_probed']} Domains ({agg['session_meta']['asn']})")
    ax1.legend(loc="upper right", fontsize=7.9)

    pdns = agg["pcap_dns_hijack"]
    https_drop = max(0, ds["control_https_rr"] - ds["isp_https_rr"])
    dnssec_drop = max(0, ds["control_dnssec"] - ds["isp_dnssec"])
    mech_labels = [
        "PCAP Forged DNS Replies\n(External Resolvers Intercepted)",
        "External Resolvers Hijacked\n(Port 53 / 5353 Probed)",
        f"HTTPS/SVCB RRs Stripped\n({ds['control_https_rr']} Control -> {ds['isp_https_rr']} ISP)",
        f"DNSSEC RRSIG/AD Lost\n({ds['control_dnssec']} Control -> {ds['isp_dnssec']} ISP)",
        "Forced SafeSearch Hijack\n(216.239.38.120 Redirect)",
        "RFC1918 Private Redirect\n(Sinkhole Outside 10.10.34.x)",
    ]
    mech_vals = [
        pdns.get("forged_count", 0),
        ds["ext_resolvers_hijacked"],
        https_drop,
        dnssec_drop,
        ds["forced_safesearch_216_239_38_120"],
        ds["private_rfc1918_redirect"],
    ]
    colors2 = ["#b91c1c", "#d97706", "#0284c7", "#7c3aed", "#ea580c", "#0f766e"]
    y2 = np.arange(len(mech_labels))
    bars2 = ax2.barh(y2, mech_vals, color=colors2, height=0.58)
    ax2.set_yticks(y2)
    ax2.set_yticklabels(mech_labels, fontsize=8.3)
    ax2.invert_yaxis()
    ax2.set_xlim(0, max(mech_vals or [1]) + 18)
    ax2.set_xlabel("Verified Forensic Events / Count")
    ax2.set_title("DNS Hijacking & Protocol Degradation Mechanisms")
    for bar, val in zip(bars2, mech_vals):
        ax2.annotate(f"{val}", xy=(val, bar.get_y() + bar.get_height() / 2), xytext=(5, 0), textcoords="offset points", ha="left", va="center", fontsize=8.5, fontweight="bold")
    f_rtt = pdns.get("forged_median_rtt_ms")
    c_rtt = pdns.get("clean_median_rtt_ms")
    ax2.text(
        0.97,
        0.06,
        f"Forged DNS Median RTT: {f_rtt if f_rtt is not None else 'N/A'} ms\n"
        f"Clean DNS Median RTT:  {c_rtt if c_rtt is not None else 'N/A'} ms\n"
        f"Forged TTLs: {pdns.get('forged_ttls', [])}",
        transform=ax2.transAxes,
        ha="right",
        va="bottom",
        fontsize=8.0,
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#fff7ed", edgecolor="#f59e0b"),
    )


def plot_synthetic_sni_ax(ax, agg, compact=False):
    syn = agg["synthetic_sni"]
    tot = max(1, syn["total"])
    op_short = agg["session_meta"]["operator"]["short_en"]
    labels = [
        f"{op_short} -> Hetzner DE\n(TLS 443 Fake SNI)",
        f"{op_short} -> Vultr DE\n(TLS 443 Fake SNI)",
        f"{op_short} -> Hetzner DE\n(HTTP 80 Host)",
        "Clean Non-Blocked\nSNIs (Both Servers)",
    ]
    blk = [syn["isp_hetzner_rst"], syn["isp_vultr_rst"], syn["isp_http_blockpage"], 0]
    okv = [tot - syn["isp_hetzner_rst"], tot - syn["isp_vultr_rst"], tot - syn["isp_http_blockpage"], syn["clean_both_servers"]]
    y = np.arange(len(labels))
    h = 0.35
    b1 = ax.barh(y - h / 2, blk, h, color="#dc2626", label=f"Blocked by {op_short} (RST / 403 NSV2)")
    b2 = ax.barh(y + h / 2, okv, h, color="#16a34a", label="Passed Cleanly (TLS_SERVER_HELLO)")
    for bars in (b1, b2):
        for bar in bars:
            w = bar.get_width()
            if w > 0:
                ax.annotate(f"{int(w)}/{tot}", xy=(w, bar.get_y() + bar.get_height() / 2), xytext=(4, 0), textcoords="offset points", va="center", fontsize=8.4, fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8.3, fontweight="bold" if compact else "normal")
    ax.invert_yaxis()
    ax.set_xlim(0, tot + 4)
    ax.set_xlabel(f"Synthetic Non-Existent FQDNs (Out of {tot})")
    ax.set_title(f"Dual-Server Synthetic SNI Trap: {syn['isp_hetzner_rst']}/{tot} Blocked Mid-Path")
    ax.legend(fontsize=7.8, loc="lower right")
    if not compact and syn["blocked_patterns"]:
        pat_txt = ", ".join(syn["blocked_patterns"][:8])
        if len(syn["blocked_patterns"]) > 8:
            pat_txt += f", +{len(syn['blocked_patterns']) - 8} more"
        ax.text(
            0.98, 0.54,
            f"Blocked Patterns ({len(syn['blocked_patterns'])}):\n{pat_txt}",
            transform=ax.transAxes, ha="right", va="center", fontsize=7.6,
            bbox=dict(boxstyle="round,pad=0.35", facecolor="#fef2f2", edgecolor="#ef4444"),
        )


def plot_geoblock_sep_ax(ax, agg):
    dpi_s = agg["dpi_summary"]
    op_short = agg["session_meta"]["operator"]["short_en"]
    sep_labels = [
        "Clean ISP & Destination\n(TLS OK, HTTP 2xx/3xx)",
        f"{op_short} TLS SNI DPI RST\n(In-Path Middlebox RST)",
        f"{op_short} Real-IP TCP/TLS Drop\n(L3/L4 Blackhole or Timeout)",
        "Foreign Geo-Block Only on IR IP\n(TLS OK -> Remote 403/421)",
        "Remote CDN/WAF on Both Paths\n(403/421 on ISP & Control)",
    ]
    sep_vals = [
        dpi_s["clean_200_count"],
        dpi_s["sni_rst_count"],
        dpi_s["tcp_tls_timeout_count"],
        len(dpi_s["geo_isp_only_403_hosts"]),
        len(dpi_s["geo_both_403_hosts"]),
    ]
    sep_cols = ["#16a34a", "#dc2626", "#7c3aed", "#0284c7", "#64748b"]
    y = np.arange(len(sep_labels))
    bars = ax.barh(y, sep_vals, color=sep_cols, height=0.55)
    for bar, v in zip(bars, sep_vals):
        ax.annotate(f"{v}", xy=(v, bar.get_y() + bar.get_height() / 2), xytext=(5, 0), textcoords="offset points", ha="left", va="center", fontsize=8.6, fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels(sep_labels, fontsize=8.3)
    ax.invert_yaxis()
    ax.set_xlim(0, max(sep_vals or [1]) + 14)
    ax.set_xlabel(f"Domains Probed at TLS & HTTP Layers (n = {dpi_s['domains_probed']})")
    ax.set_title(f"{op_short} Censorship vs Foreign Destination Geo-Blocks")


def plot_pcap_rst_hist_ax(ax, agg, rsts, compact=False):
    rst_s = agg["pcap_dpi_rst"]
    srv_rtts = [r["server_rtt_ms"] for r in rsts if r.get("server_rtt_ms") is not None]
    rst_delays = [r["rst_after_ch_ms"] for r in rsts if r.get("rst_after_ch_ms") is not None]
    if not rst_delays or not srv_rtts:
        ax.axis("off")
        ax.text(0.5, 0.5, f"PCAP Injected RST Events: {rst_s.get('n_events', 0)}\n(Insufficient events for timing histogram)", ha="center", va="center", fontsize=10, fontweight="bold")
        return
    hi = max(max(srv_rtts), max(rst_delays), 250) + 20
    bins = np.linspace(0, min(hi, 500), 30)
    ax.hist(rst_delays, bins=bins, alpha=0.82, color="#dc2626", edgecolor="#991b1b", label=f"Injected RST Delay (n={len(rst_delays)})")
    ax.hist(srv_rtts, bins=bins, alpha=0.62, color="#0284c7", edgecolor="#0369a1", label=f"Remote Server RTT (n={len(srv_rtts)})")
    med_rst = rst_s["median_rst_delay_ms"]
    med_srv = rst_s["median_server_rtt_ms"]
    if med_rst is not None:
        ax.axvline(med_rst, color="#991b1b", linestyle="--", lw=1.8, label=f"Median RST: {med_rst:.2f} ms")
    if med_srv is not None:
        ax.axvline(med_srv, color="#0369a1", linestyle="--", lw=1.8, label=f"Median Server: {med_srv:.2f} ms")
    ax.set_xlabel("Delay After ClientHello (ms)")
    ax.set_ylabel("Captured Flows")
    dom_ttl = rst_s.get("dominant_rst_ttl")
    dom_n = rst_s.get("n_dominant_ttl", 0)
    n_ev = rst_s.get("n_events", 0)
    ax.set_title("PCAP Timing Proof: Injected RSTs vs Real Server RTT")
    ax.legend(fontsize=7.5 if compact else 8.0, loc="upper right")
    box_txt = (
        f"Events: {n_ev}\n"
        f"Top TTL={dom_ttl}: {dom_n}/{n_ev}\n"
        f"Early RST (< RTT): {rst_s.get('n_early_rst', 0)}/{n_ev}\n"
        f"Mann-Whitney p = {fmt_pval(rst_s.get('mannwhitney_u_less_pvalue'))}"
    )
    ax.text(
        0.97, 0.52 if compact else 0.56, box_txt,
        transform=ax.transAxes, ha="right", va="center", fontsize=7.8, fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#fef2f2", edgecolor="#ef4444"),
    )


def plot_evasion_matrix_ax(ax, d2):
    modes = ["normal", "tls12", "pad1800", "ech_grease", "split_5b", "split_midsni", "split_2b", "rec_split_2", "rec_split_5"]
    mode_labels = ["Normal", "TLS 1.2", "Pad 1800B", "ECH GREASE", "Split 5B", "Mid-SNI", "Split 2B", "RecSplit 2B", "RecSplit 5B"]
    hosts = [e["host"] for e in d2.get("evasion_matrix", [])]
    if not hosts:
        ax.axis("off")
        return
    code_map = {"TLS_SERVER_HELLO": 2, "TLS_ALERT_2_40": 1, "TLS_ALERT_2_50": 1, "TLS_TIMEOUT": 0, "TCP_TIMEOUT": 0, "TCP_RST_INJECTED": -1}
    mat = np.zeros((len(hosts), len(modes)))
    for i, e in enumerate(d2["evasion_matrix"]):
        for j, m in enumerate(modes):
            out = e["modes"][m]["outcome"]
            mat[i, j] = code_map.get(out, 0)
    cmap = mcolors.ListedColormap(["#dc2626", "#94a3b8", "#f59e0b", "#16a34a"])
    norm = mcolors.BoundaryNorm([-1.5, -0.5, 0.5, 1.5, 2.5], cmap.N)
    ax.imshow(mat, cmap=cmap, norm=norm, aspect="auto")
    ax.set_xticks(np.arange(len(mode_labels)))
    ax.set_xticklabels(mode_labels, rotation=28, ha="right", fontsize=8.0)
    ax.set_yticks(np.arange(len(hosts)))
    ax.set_yticklabels(hosts, fontsize=7.8)
    ax.set_title(f"DPI Parser Matrix ({len(hosts)} Targets x 9 ClientHello Shapes)")
    patches = [
        mpatches.Patch(color="#dc2626", label="TCP_RST_INJECTED (DPI Match)"),
        mpatches.Patch(color="#16a34a", label="TLS_SERVER_HELLO (Bypassed)"),
        mpatches.Patch(color="#f59e0b", label="TLS_ALERT"),
        mpatches.Patch(color="#94a3b8", label="TCP/TLS Timeout"),
    ]
    ax.legend(handles=patches, loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2, fontsize=7.4)


def plot_cloud_matrix_ax(ax, agg, compact=False):
    by_p = agg["cloud_summary"]["by_provider"]
    provs = sorted(
        by_p.keys(),
        key=lambda p: (
            -(
                by_p[p].get("ISP_L3_L4_BLACKHOLE", 0)
                + by_p[p].get("ISP_DPI_TLS_RST", 0)
                + by_p[p].get("ISP_TLS_DISRUPTED", 0)
                + by_p[p].get("ISP_CORE_ROUTING_LOOP", 0)
                + by_p[p].get("ISP_TCP_RST_BLOCKED", 0)
            ),
            p,
        ),
    )
    ok_v = np.array([by_p[p].get("OK_BOTH", 0) + by_p[p].get("OK_DIRECT", 0) for p in provs])
    rst_v = np.array([by_p[p].get("ISP_DPI_TLS_RST", 0) + by_p[p].get("ISP_TCP_RST_BLOCKED", 0) for p in provs])
    bh_v = np.array([by_p[p].get("ISP_L3_L4_BLACKHOLE", 0) for p in provs])
    ot_v = np.array([by_p[p].get("ISP_TLS_DISRUPTED", 0) + by_p[p].get("ISP_CORE_ROUTING_LOOP", 0) for p in provs])

    y = np.arange(len(provs))
    op_short = agg["session_meta"]["operator"]["short_en"]
    ax.barh(y, ok_v, color="#16a34a", label=f"OK ({int(ok_v.sum())})")
    ax.barh(y, rst_v, left=ok_v, color="#dc2626", label=f"DPI TLS RST ({int(rst_v.sum())})")
    ax.barh(y, bh_v, left=ok_v + rst_v, color="#1e293b", label=f"L3/L4 Blackhole ({int(bh_v.sum())})")
    ax.barh(y, ot_v, left=ok_v + rst_v + bh_v, color="#7c3aed", label=f"TLS Drop / Loop ({int(ot_v.sum())})")
    totals = ok_v + rst_v + bh_v + ot_v
    fails = rst_v + bh_v + ot_v
    for idx, (tot, fl) in enumerate(zip(totals, fails)):
        tag = f" {fl}/{tot} fail" if fl > 0 else f" {tot}/{tot} OK"
        ax.text(tot + 0.15, idx, tag, va="center", ha="left", fontsize=7.8, fontweight="bold", color="#b91c1c" if fl > 0 else "#15803d")
    ax.set_yticks(y)
    ax.set_yticklabels(provs, fontsize=8.3, fontweight="bold" if compact else "normal")
    ax.invert_yaxis()
    ax.set_xlim(0, (float(max(totals)) if len(totals) else 1.0) + 2.5)
    cs = agg["cloud_summary"]
    ctl_info = f"; Control={cs['control_tcp_ok']}/{cs['total_endpoints']} OK" if agg["session_meta"]["has_control"] else ""
    ax.set_xlabel(f"Cloud/Dev Endpoints (Total={cs['total_endpoints']}{ctl_info})")
    ax.set_title(f"{cs['isp_disrupted']}/{cs['total_endpoints']} ({cs['disrupted_pct']}%) Disrupted on {op_short}")
    ax.legend(loc="lower right", fontsize=7.4)


def plot_mtr_loops_ax(ax, agg):
    mtrs = agg["cloud_summary"].get("mtr_loop_summary") or []
    if not mtrs:
        ax.axis("off")
        ax.text(0.5, 0.5, "No MTR traces captured", ha="center", va="center")
        return
    ordered = sorted(mtrs, key=lambda m: (0 if m["has_loop"] else 1, -m["max_hop"], -m["worst_ms"]))[:7]
    y2 = np.arange(len(ordered))
    hops = [m["max_hop"] for m in ordered]
    cols2 = ["#7c3aed" if m["has_loop"] else ("#1e293b" if not m["reached"] else "#16a34a") for m in ordered]
    bars2 = ax.barh(y2, hops, color=cols2, height=0.56)
    ax.axvline(30, color="#dc2626", linestyle=":", linewidth=1.8, label="MTR 30-Hop TTL Limit")
    for bar, m in zip(bars2, ordered):
        if m["has_loop"]:
            loop_str = ", ".join(m["loop_ips"][:3]) if m["loop_ips"] else "TTL Loop"
            desc = f"{loop_str} | {m['last_loss_pct']:.0f}% loss ({m['worst_ms']:.0f}ms)"
        elif not m["reached"]:
            desc = f"Unreached ({m['last_loss_pct']:.0f}% loss)"
        else:
            desc = f"Reached cleanly ({m['worst_ms']:.0f}ms)"
        ax.text(0.8, bar.get_y() + bar.get_height() / 2, desc, va="center", ha="left", fontsize=7.4, color="#ffffff", fontweight="bold")
        ax.annotate(f"{m['max_hop']} hops", xy=(m["max_hop"], bar.get_y() + bar.get_height() / 2), xytext=(4, 0), textcoords="offset points", va="center", fontsize=8.0, fontweight="bold")
    ax.set_yticks(y2)
    ax.set_yticklabels([f"{m['label']}\n{m['ip']}" for m in ordered], fontsize=7.8)
    ax.invert_yaxis()
    ax.set_xlim(0, max(hops or [30]) + 6.5)
    ax.set_xlabel("Traceroute / MTR Hop Count")
    ax.set_title(f"MPLS / Routing Path & Core Loops ({agg['session_meta']['asn']})")
    ax.legend(loc="lower right", fontsize=7.8)


def plot_protocols_ax(ax, agg, d4, compact=False):
    ps = agg["protocols_summary"]
    has_ctl = agg["session_meta"]["has_control"]
    op_short = agg["session_meta"]["operator"]["short_en"]
    suites = [
        f"PortQuiz TCP Ports\n({ps['tcp_ports_total']} Ports Incl. 853)",
        f"Int'l DoT TCP/853\n({ps['dot_intl_total']} Providers)",
        f"DoH Domain HTTPS\n({ps['doh_domain_total']} Providers)",
        f"DoQ QUIC UDP/853\n({ps['doq_853_total']} Providers)",
        "NTP time.google.com\n(UDP/123 Sync)",
        f"STUN WebRTC UDP\n({ps['stun_total']} Servers)",
    ]

    def pct(n, d):
        return (100.0 * n / d) if d else 0.0

    isp_pct = [
        pct(ps["tcp_ports_isp_ok"], ps["tcp_ports_total"]),
        pct(ps["dot_intl_isp_ok"], ps["dot_intl_total"]),
        pct(ps["doh_domain_isp_ok"], ps["doh_domain_total"]),
        pct(ps["doq_853_isp_ok"], ps["doq_853_total"]),
        100.0 if ps["ntp_google_isp_ok"] else 0.0,
        pct(ps["stun_isp_ok"], ps["stun_total"]),
    ]
    isp_lbl = [
        f"{ps['tcp_ports_isp_ok']}/{ps['tcp_ports_total']}",
        f"{ps['dot_intl_isp_ok']}/{ps['dot_intl_total']}",
        f"{ps['doh_domain_isp_ok']}/{ps['doh_domain_total']}",
        f"{ps['doq_853_isp_ok']}/{ps['doq_853_total']}",
        "OK" if ps["ntp_google_isp_ok"] else "FAIL",
        f"{ps['stun_isp_ok']}/{ps['stun_total']}",
    ]
    y = np.arange(len(suites))
    if has_ctl:
        ctl_pct = [
            pct(ps["tcp_ports_ctl_ok"], ps["tcp_ports_total"]),
            pct(ps["dot_intl_ctl_ok"], ps["dot_intl_total"]),
            pct(ps["doh_domain_ctl_ok"], ps["doh_domain_total"]),
            pct(ps["doq_853_ctl_ok"], ps["doq_853_total"]),
            100.0 if ps["ntp_google_ctl_ok"] else 0.0,
            pct(ps["stun_ctl_ok"], ps["stun_total"]),
        ]
        ctl_lbl = [
            f"{ps['tcp_ports_ctl_ok']}/{ps['tcp_ports_total']}",
            f"{ps['dot_intl_ctl_ok']}/{ps['dot_intl_total']}",
            f"{ps['doh_domain_ctl_ok']}/{ps['doh_domain_total']}",
            f"{ps['doq_853_ctl_ok']}/{ps['doq_853_total']}",
            "OK" if ps["ntp_google_ctl_ok"] else "FAIL",
            f"{ps['stun_ctl_ok']}/{ps['stun_total']}",
        ]
        h = 0.35
        b1 = ax.barh(y - h / 2, isp_pct, h, label=f"{op_short} Direct", color="#dc2626")
        b2 = ax.barh(y + h / 2, ctl_pct, h, label="Control Clean Net", color="#0284c7")
        for bar, txt in zip(b2, ctl_lbl):
            ax.annotate(txt, xy=(max(bar.get_width(), 2), bar.get_y() + bar.get_height() / 2), xytext=(4, 0), textcoords="offset points", va="center", fontsize=8.0, fontweight="bold", color="#0369a1")
    else:
        b1 = ax.barh(y, isp_pct, 0.52, label=f"{op_short} Direct", color="#dc2626")

    for bar, txt in zip(b1, isp_lbl):
        ax.annotate(txt, xy=(max(bar.get_width(), 2), bar.get_y() + bar.get_height() / 2), xytext=(4, 0), textcoords="offset points", va="center", fontsize=8.0, fontweight="bold", color="#991b1b")

    ax.set_yticks(y)
    ax.set_yticklabels(suites, fontsize=8.3, fontweight="bold" if compact else "normal")
    ax.invert_yaxis()
    ax.set_xlim(0, 128)
    ax.set_xlabel("Protocol Pass Rate (%)")
    ax.set_title("Encrypted DNS (DoT/DoH/DoQ) & Core Protocols")
    ax.legend(loc="lower right", fontsize=7.9)


def plot_dot_table_ax(ax, d4, agg):
    ax.axis("off")
    op_short = agg["session_meta"]["operator"]["short_en"]
    has_ctl = agg["session_meta"]["has_control"]
    rows = []
    for r in d4.get("dot", []):
        if r["label"] == "Shecan":
            continue
        m_st = "OK" if r["isp"]["dns_ok"] else ("RST" if "Reset" in str(r["isp"].get("err", "")) else ("Banner" if "WRONG_VERSION" in str(r["isp"].get("err", "")) else "Timeout"))
        c_st = ("OK" if (r.get("control") or {}).get("dns_ok") else "Banner/Fail") if has_ctl else "DirectOnly"
        rows.append([f"{r['label']} ({r['ip']}:853)", m_st, c_st])
    for r in d4.get("quic", []):
        if r["port"] == 853:
            m_st = "OK" if r["isp_aioquic"]["ok"] else "Timeout"
            c_st = (f"OK ({r['control_aioquic'].get('reply_bytes', 0)}B)" if (r.get("control_aioquic") or {}).get("ok") else "Fail") if has_ctl else "DirectOnly"
            rows.append([f"{r['label']} UDP/853", m_st, c_st])
    if not rows:
        return
    tbl = ax.table(cellText=rows, colLabels=["Protocol / Endpoint", f"{op_short} Direct", "Control Net"], loc="center", cellLoc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8.1)
    tbl.scale(1.0, 1.48)
    for (r_idx, c_idx), cell in tbl.get_celld().items():
        if r_idx == 0:
            cell.set_facecolor("#0f172a")
            cell.set_text_props(color="#ffffff", fontweight="bold")
        elif c_idx == 1:
            txt = cell.get_text().get_text()
            cell.set_facecolor("#ecfdf5" if txt in ("OK", "Banner") else "#fee2e2")
        elif c_idx == 2:
            cell.set_facecolor("#dcfce7")
    ax.set_title("Per-Provider Port 853 Breakdown", pad=8)


def plot_speed_ax(ax, agg, d5, compact=False):
    sp = d5.get("speed_benchmarks", [])
    if compact and len(sp) > 8:
        prefer = {"Ubuntu-Archive-5MB", "Cloudflare-5MB", "Vultr-FRA-5MB", "GitHub-Release-4MB", "Debian-146.75.118.132", "Debian-151.101.18.132", "Google-DL-5MB", "OVH-Proof-5MB"}
        sp = [s for s in sp if s["label"] in prefer] or sp[:8]
    labels = [s["label"].replace("-5MB", "").replace("-4MB", "") for s in sp]
    isp_vals = [s["isp"]["mbps"] for s in sp]
    has_ctl = agg["session_meta"]["has_control"]
    op_short = agg["session_meta"]["operator"]["short_en"]

    y = np.arange(len(labels))
    if has_ctl and not compact:
        ctl_vals = [(s.get("control") or {}).get("mbps") or 0.0 for s in sp]
        h = 0.36
        b1 = ax.barh(y - h / 2, isp_vals, h, color=["#dc2626" if (v < 0.5 or s["isp"]["rc"] != 0) else "#16a34a" for v, s in zip(isp_vals, sp)], label=f"{op_short} Direct")
        ax.barh(y + h / 2, ctl_vals, h, color="#0284c7", label="Control Net")
        max_x = max(isp_vals + ctl_vals + [5.0])
    else:
        b1 = ax.barh(y, isp_vals, 0.58, color=["#dc2626" if (v < 0.5 or s["isp"]["rc"] != 0) else "#16a34a" for v, s in zip(isp_vals, sp)])
        max_x = max(isp_vals + [5.0])

    for bar, s in zip(b1, sp):
        v = bar.get_width()
        tag = f" {v:.2f} Mbps" if s["isp"]["rc"] == 0 else f" {v:.2f} Mbps (ERR {s['isp']['rc']})"
        ax.text(v + 0.2, bar.get_y() + bar.get_height() / 2, tag, va="center", ha="left", fontsize=7.6, fontweight="bold", color="#b91c1c" if (v < 0.5 or s["isp"]["rc"] != 0) else "#15803d")

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8.1, fontweight="bold" if compact else "normal")
    ax.invert_yaxis()
    ax.set_xlim(0, max_x + 7.5)
    ax.set_xlabel("Measured Transfer Speed (Mbps)")
    ax.set_title(f"Download Benchmarks ({op_short} Max: {agg['speed_summary']['max_isp_mbps']:.2f} Mbps)")
    if not compact:
        p1 = mpatches.Patch(color="#16a34a", label="Fast/Healthy")
        p2 = mpatches.Patch(color="#dc2626", label="Stalled/Blocked")
        handles = [p1, p2]
        if has_ctl:
            handles.append(mpatches.Patch(color="#0284c7", label="Control Net"))
        ax.legend(handles=handles, loc="lower right", fontsize=7.8)


def plot_fastly_thresholds_ax(ax, d5):
    ft_rows = []
    for f_row in d5.get("fastly_thresholds", []):
        if f_row["ip"] == "151.101.18.132" and f_row["scheme"] == "http":
            ft_rows.append((f"18.132 HTTP {f_row['range']}", f_row["isp"]["bytes"], f_row["isp"]["rc"]))
    for f_row in d5.get("fastly_thresholds", []):
        if (f_row["ip"], f_row["scheme"], f_row["range"]) in (
            ("151.101.18.132", "https", "0-20479"),
            ("151.101.18.132", "https", "FULL"),
            ("146.75.118.132", "http", "FULL"),
            ("151.101.130.132", "http", "FULL"),
        ):
            ft_rows.append((f"{f_row['ip'].split('.', 2)[-1]} {f_row['scheme'].upper()} {f_row['range']}", f_row["isp"]["bytes"], f_row["isp"]["rc"]))
    if not ft_rows:
        ax.axis("off")
        return
    lbls = [r[0] for r in ft_rows]
    kib = [r[1] / 1024.0 for r in ft_rows]
    cols = ["#dc2626" if r[2] != 0 else "#16a34a" for r in ft_rows]
    y = np.arange(len(lbls))
    bars = ax.barh(y, kib, color=cols, height=0.58)
    ax.axvline(5552 / 1024.0, color="#b45309", linestyle="--", linewidth=1.6, label="5,552 B Reference")
    for bar, (_, b_raw, rc) in zip(bars, ft_rows):
        kb = b_raw / 1024.0
        st = "OK" if rc == 0 else f"ERR rc={rc}"
        ax.annotate(f" {b_raw:,} B ({st})", xy=(kb, bar.get_y() + bar.get_height() / 2), xytext=(4, 0), textcoords="offset points", va="center", fontsize=7.6, fontweight="bold", color="#991b1b" if rc != 0 else "#166534")
    ax.set_yticks(y)
    ax.set_yticklabels(lbls, fontsize=7.8)
    ax.invert_yaxis()
    ax.set_xlim(0, max(kib + [20]) * 1.35)
    ax.set_xlabel("Transferred Bytes Before Completion or Stall (KiB)")
    ax.set_title("Fastly Anycast Edge Threshold Probes")
    ax.legend(loc="lower right", fontsize=7.8)


def plot_jitter_ax(ax, agg, d5):
    jb = [j for j in d5.get("jitter_bursts", []) if j["isp"].get("p50_ms") is not None]
    if not jb:
        ax.axis("off")
        return
    j_labels = [j["label"] for j in jb]
    p50s = [j["isp"]["p50_ms"] for j in jb]
    p95s = [j["isp"]["p95_ms"] for j in jb]
    stdevs = [j["isp"]["stdev_ms"] for j in jb]
    x = np.arange(len(j_labels))
    w = 0.26
    ax.bar(x - w, p50s, w, label="Median p50 (ms)", color="#0284c7")
    ax.bar(x, p95s, w, label="Tail p95 (ms)", color="#f59e0b")
    ax.bar(x + w, stdevs, w, label="Jitter StDev (ms)", color="#dc2626")
    for idx, (m95, sd) in enumerate(zip(p95s, stdevs)):
        ax.annotate(f"{sd:.2f}", xy=(idx + w, sd), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=7.6, fontweight="bold", color="#991b1b")
        ax.annotate(f"{m95:.0f}", xy=(idx, m95), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=7.4)
    ax.set_xticks(x)
    ax.set_xticklabels(j_labels, rotation=20, ha="right", fontsize=8.2)
    ax.set_ylabel("Latency / Jitter (ms)")
    ax.set_ylim(0, max(p95s or [50]) + 55)
    ax.set_title("40-Packet Burst Latency & Jitter")
    ax.legend(loc="upper left", fontsize=7.9)
    ss = agg["speed_summary"]
    ax.text(
        0.97, 0.96,
        f"Local GW Jitter: {ss['local_gw_jitter_ms']} ms\nMax Remote Jitter: {ss['remote_max_jitter_ms']} ms ({ss['remote_max_jitter_label']})",
        transform=ax.transAxes, ha="right", va="top", fontsize=7.9,
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#ecfeff", edgecolor="#0284c7"),
    )


def plot_history_or_impact_ax(ax, agg, compact=False):
    hist = agg.get("history_comparison") or []
    if len(hist) >= 2:
        metrics = ["Forged DPI\nRST Events", "Cloud Fail\nRate (%)", "Cloud Fail\nCount", "DNS Sinkhole\n(10.10.34.x)", "Top TTL\nShare (%)"]
        x = np.arange(len(metrics))
        n_runs = len(hist)
        w = min(0.28, 0.72 / n_runs)
        palette = ["#64748b", "#d97706", "#dc2626", "#7c3aed"]
        max_h = 10
        for r_idx, run in enumerate(hist[-4:]):
            vals = [run["rst_events"], run["cloud_fail_pct"], run["cloud_fail_count"], run["dns_sinkholes"], run["dominant_ttl_share_pct"]]
            max_h = max(max_h, max(vals))
            offset = (r_idx - (min(n_runs, 4) - 1) / 2.0) * w
            bars = ax.bar(x + offset, vals, w * 0.9, color=palette[r_idx % len(palette)], label=run["label"][:28])
            for idx, bar in enumerate(bars):
                hv = bar.get_height()
                txt = f"{hv:.1f}%" if idx in (1, 4) else f"{int(hv)}"
                ax.annotate(txt, xy=(bar.get_x() + bar.get_width() / 2, hv), xytext=(0, 2), textcoords="offset points", ha="center", fontsize=6.2 if compact else 7.2, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels(metrics, rotation=16 if not compact else 0, ha="right" if not compact else "center", fontsize=7.8)
        ax.set_ylabel("Count / %")
        ax.set_ylim(0, max_h * 1.2 + 10)
        ax.set_title(f"Multi-Session Progression ({len(hist)} Audited Sessions)")
        ax.legend(fontsize=7.3, loc="upper right")
    else:
        ds = agg["dns_summary"]
        syn = agg["synthetic_sni"]
        cs = agg["cloud_summary"]
        ps = agg["protocols_summary"]
        rst = agg["pcap_dpi_rst"]
        cats = ["DNS Tampered\n(% Domains)", "Synthetic SNI\nBlocked (%)", "Cloud Infra\nFailed (%)", "DoT/DoQ 853\nBlocked (%)", "DPI RST\nEarly Share (%)"]
        vals = [
            round(100.0 * ds["total_dns_blocked"] / max(1, ds["domains_probed"]), 1),
            round(100.0 * syn["isp_hetzner_rst"] / max(1, syn["total"]), 1),
            cs["disrupted_pct"],
            round(100.0 * (ps["dot_intl_total"] - ps["dot_intl_isp_ok"]) / max(1, ps["dot_intl_total"]), 1),
            round(100.0 * rst.get("n_early_rst", 0) / max(1, rst.get("n_events", 1)), 1) if rst.get("n_events") else 0.0,
        ]
        cols = ["#d97706", "#dc2626", "#7c3aed", "#0284c7", "#991b1b"]
        x = np.arange(len(cats))
        bars = ax.bar(x, vals, width=0.52, color=cols)
        for bar, v in zip(bars, vals):
            ax.annotate(f"{v:.1f}%", xy=(bar.get_x() + bar.get_width() / 2, v), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8.4, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels(cats, fontsize=8.0, fontweight="bold" if compact else "normal")
        ax.set_ylabel("Measured Interference (%)")
        ax.set_ylim(0, 118)
        ax.set_title(f"Censorship & Degradation Footprint ({agg['session_meta']['asn']})")


def generate_all_charts(charts_dir, agg, d1, d2, d3, d4, d5, rsts):
    charts_dir.mkdir(parents=True, exist_ok=True)
    setup_mpl_style(9.5)
    tag = _op_tag(agg, opsec_safe=False)

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15.5, 6.4), gridspec_kw={"width_ratios": [1.38, 1.0]})
    plot_dns_layers_ax(a1, a2, agg)
    fig.suptitle(f"{tag} - Multi-Layer Filtering & DNS Manipulation", fontsize=12.2, fontweight="bold", y=0.98)
    _brand_footer(fig)
    plt.tight_layout(rect=[0, 0.02, 1, 0.94])
    plt.savefig(charts_dir / "01_dns_layers_and_resolver_hijack.png", dpi=300)
    plt.close(fig)

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15.5, 6.2), gridspec_kw={"width_ratios": [1.15, 1.0]})
    plot_synthetic_sni_ax(a1, agg)
    plot_geoblock_sep_ax(a2, agg)
    fig.suptitle(f"{tag} - Synthetic SNI Proof & Geo-Block Separation", fontsize=12.2, fontweight="bold", y=0.98)
    _brand_footer(fig)
    plt.tight_layout(rect=[0, 0.02, 1, 0.94])
    plt.savefig(charts_dir / "02_dual_synthetic_sni_and_geoblock.png", dpi=300)
    plt.close(fig)

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15.5, 6.4), gridspec_kw={"width_ratios": [1.0, 1.25]})
    plot_pcap_rst_hist_ax(a1, agg, rsts)
    plot_evasion_matrix_ax(a2, d2)
    fig.suptitle(f"{tag} - In-Path Middlebox RST Injection & Evasion Matrix", fontsize=12.2, fontweight="bold", y=0.98)
    _brand_footer(fig)
    plt.tight_layout(rect=[0, 0.05, 1, 0.94])
    plt.savefig(charts_dir / "03_pcap_rst_ttl_timing_and_evasion.png", dpi=300)
    plt.close(fig)

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15.5, 6.4), gridspec_kw={"width_ratios": [1.3, 1.0]})
    plot_cloud_matrix_ax(a1, agg)
    plot_mtr_loops_ax(a2, agg)
    fig.suptitle(f"{tag} - Cloud Infrastructure Failures & Core Routing Loops", fontsize=12.2, fontweight="bold", y=0.98)
    _brand_footer(fig)
    plt.tight_layout(rect=[0, 0.02, 1, 0.94])
    plt.savefig(charts_dir / "04_cloud_infra_57_matrix_and_loops.png", dpi=300)
    plt.close(fig)

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15.5, 6.2), gridspec_kw={"width_ratios": [1.15, 1.0]})
    plot_protocols_ax(a1, agg, d4)
    plot_dot_table_ax(a2, d4, agg)
    fig.suptitle(f"{tag} - Encrypted DNS (DoT/DoH/DoQ) & Core Protocols", fontsize=12.2, fontweight="bold", y=0.98)
    _brand_footer(fig)
    plt.tight_layout(rect=[0, 0.02, 1, 0.94])
    plt.savefig(charts_dir / "05_protocols_dot_doh_doq_ports.png", dpi=300)
    plt.close(fig)

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15.5, 6.4), gridspec_kw={"width_ratios": [1.18, 1.0]})
    plot_speed_ax(a1, agg, d5)
    plot_fastly_thresholds_ax(a2, d5)
    fig.suptitle(f"{tag} - Selective Speed Collapse & Fastly Edge Thresholds", fontsize=12.2, fontweight="bold", y=0.98)
    _brand_footer(fig)
    plt.tight_layout(rect=[0, 0.02, 1, 0.94])
    plt.savefig(charts_dir / "06_throughput_and_fastly_mss_threshold.png", dpi=300)
    plt.close(fig)

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15.5, 6.2), gridspec_kw={"width_ratios": [1.05, 1.05]})
    plot_jitter_ax(a1, agg, d5)
    plot_history_or_impact_ax(a2, agg)
    fig.suptitle(f"{tag} - Burst Jitter vs Interference Summary", fontsize=12.2, fontweight="bold", y=0.98)
    _brand_footer(fig)
    plt.tight_layout(rect=[0, 0.02, 1, 0.94])
    plt.savefig(charts_dir / "07_jitter_burst_and_summary.png", dpi=300)
    plt.close(fig)

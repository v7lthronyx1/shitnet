import hashlib
import json
from . import APP_NAME, AUTHOR, BRAND, __version__
from .analytics import fmt_num, fmt_pval


def _format_loop_summary_fa(mtr_loops):
    looped = [m for m in mtr_loops if m["has_loop"]]
    if not looped:
        return "در تست MTR حلقه داخلی تا هاپ ۳۰ مشاهده نشد"
    parts = []
    for m in looped[:4]:
        ips = " / ".join(m["loop_ips"][:3]) if m["loop_ips"] else "TTL=30"
        parts.append(f"`{m['label']} ({m['ip']})` درون `{ips}` (هاپ `{m['max_hop']}`، اتلاف `{m['last_loss_pct']:.0f}%`، بیشینه `{m['worst_ms']} ms`)")
    return "؛ ".join(parts)


def _format_loop_summary_en(mtr_loops):
    looped = [m for m in mtr_loops if m["has_loop"]]
    if not looped:
        return "No hop-30 internal loop detected in MTR traces"
    parts = []
    for m in looped[:4]:
        ips = " / ".join(m["loop_ips"][:3]) if m["loop_ips"] else "TTL=30"
        parts.append(f"`{m['label']} ({m['ip']})` looping on `{ips}` (hop `{m['max_hop']}`, loss `{m['last_loss_pct']:.0f}%`, worst `{m['worst_ms']} ms`)")
    return "; ".join(parts)


def write_reports(base_dir, raw_dir, agg, d2, d3, d4, d5):
    meta = agg["session_meta"]
    op = meta["operator"]
    ds = agg["dns_summary"]
    dpi_s = agg["dpi_summary"]
    syn = agg["synthetic_sni"]
    rst = agg["pcap_dpi_rst"]
    pdns = agg["pcap_dns_hijack"]
    cs = agg["cloud_summary"]
    ps = agg["protocols_summary"]
    ss = agg["speed_summary"]
    fastly_s = agg["fastly_stall"]
    fastly_retrans = agg["pcap_fastly_tcp"].get("server_retransmissions", 0)

    pval_str = fmt_pval(rst.get("mannwhitney_u_less_pvalue"))
    dom_ttl = rst.get("dominant_rst_ttl")
    dom_n = rst.get("n_dominant_ttl", 0)
    dom_pct = rst.get("dominant_ttl_share_pct", 0.0)
    ctl_ip = meta["control_public_ip"] or ("مقایسه تک‌خط مستقیم بدون VPN" if not meta["has_control"] else "N/A")
    ctl_ip_en = meta["control_public_ip"] or ("Direct-Only Forensics (No VPN)" if not meta["has_control"] else "N/A")

    loop_fa = _format_loop_summary_fa(cs.get("mtr_loop_summary", []))
    loop_en = _format_loop_summary_en(cs.get("mtr_loop_summary", []))

    blocked_syn_str = "، ".join(f"`{x}`" for x in syn["blocked_patterns"][:8]) or "موردی ثبت نشد"
    clean_syn_str = "، ".join(f"`{x}`" for x in syn["clean_patterns"][:6]) or "ندارد"
    geo_str = "، ".join(f"`{x}`" for x in dpi_s["geo_isp_only_403_hosts"][:8]) or "موردی ثبت نشد"
    split2b_str = "، ".join(f"`{x}`" for x in agg["split_2b_bypass_hosts"][:8]) or "موردی ثبت نشد"
    stalled_str = "، ".join(f"`{x}`" for x in ss["stalled_labels"][:6]) or "همه سالم"

    history_section_fa = ""
    history_section_en = ""
    hist = agg.get("history_comparison") or []
    if len(hist) >= 2:
        rows_fa = "\n".join(
            f"| `{r['label']}` | `{r['ip']}` | `{r['rst_events']}` (`{r['dominant_ttl_share_pct']}%`) | `{r['cloud_fail_count']}/{r['cloud_total']} ({r['cloud_fail_pct']}%)` | `{r['dns_sinkholes']}` |"
            for r in hist
        )
        history_section_fa = f"""
## ۰. مقایسه دقیق با نشست‌های قبلی (اثبات تداوم و تشدید اختلال)

| نشست / اتصال | آی‌پی عمومی اپراتور | تزریق `TCP RST` (سهم TTL غالب) | اختلال زیرساخت ابری | ربایش Sinkhole DNS |
| :--- | :--- | :--- | :--- | :--- |
{rows_fa}

---
"""
        rows_en = "\n".join(
            f"| `{r['label']}` | `{r['ip']}` | `{r['rst_events']}` (`{r['dominant_ttl_share_pct']}%`) | `{r['cloud_fail_count']}/{r['cloud_total']} ({r['cloud_fail_pct']}%)` | `{r['dns_sinkholes']}` |"
            for r in hist
        )
        history_section_en = f"""
## Previous Session Progression Comparison

| Session / Interface | Audited Public IP | Forged `TCP RST` (Top-TTL Share) | Cloud Disruption | DNS Sinkholes |
| :--- | :--- | :--- | :--- | :--- |
{rows_en}

"""

    fastly_note_fa = (
        f"توقف مسیر `151.101.18.132` سر `{fastly_s['stall_bytes']:,} B` (`{fastly_retrans}` ارسال مجدد)"
        if fastly_s["stalled"]
        else f"مسیر `151.101.18.132` بدون توقف با سرعت `{fastly_s['mbps']} Mbps`"
    )
    fastly_note_en = (
        f"`151.101.18.132` stalled at `{fastly_s['stall_bytes']:,} B` (`{fastly_retrans}` retransmissions)"
        if fastly_s["stalled"]
        else f"`151.101.18.132` completed at `{fastly_s['mbps']} Mbps`"
    )

    ctl_dns_col_fa = (
        f"بازگشت IP واقعی، `HTTPS RR = {ds['control_https_rr']}`، `DNSSEC = {ds['control_dnssec']}`"
        if meta["has_control"]
        else "حالت تک‌خط مستقیم (سنجش RFC1918 / Sinkhole / DoH)"
    )
    ctl_cloud_col_fa = f"`{cs['control_tcp_ok']}/{cs['total_endpoints']} TCP OK`" if meta["has_control"] else "تست مستقیم IP پین‌شده"
    ctl_proto_col_fa = (
        f"DoT: `{ps['dot_intl_ctl_ok']}/{ps['dot_intl_total']}`، DoQ: `{ps['doq_853_ctl_ok']}/{ps['doq_853_total']}`، PortQuiz: `{ps['tcp_ports_ctl_ok']}/{ps['tcp_ports_total']}`"
        if meta["has_control"]
        else "حالت مستقیم"
    )

    report_fa = f"""# گزارش جامع فنی-کارشناسی و جرم‌یابی شبکه اپراتور {op['name_fa']} ({meta['asn']})

- **تولیدشده توسط ابزار متن‌باز**: `{APP_NAME} v{__version__}` (`{BRAND}` — `{AUTHOR}`)
- **زمان جمع‌آوری شواهد (UTC)**: `{meta['timestamp_utc']}`
- **نوع اتصال و رابط شبکه**: `{meta['connection_type']}` روی اینترفیس `{meta['interface']}` (حالت ممیزی: `{meta['mode']}`)
- **آی‌پی عمومی اپراتور تحت ممیزی**: `{meta['isp_public_ip']}` (`{meta['asn']}`، پیشوند `{meta['prefix']}` — `{op['legal_fa']}`)
- **گره کنترل سالم**: `{ctl_ip}`

---
{history_section_fa}
## ۱. خلاصه اجرایی یافته‌های کلیدی (مستندات عددی از PCAP و تست‌های فعال)

| محور فنی | یافته قطعی روی {op['name_fa']} (`{meta['isp_public_ip']}`) | وضعیت خط کنترل | معنا و مستند حقوقی-فنی |
| :--- | :--- | :--- | :--- |
| **ربایش و جعل DNS (PCAP)** | **{pdns.get('forged_count', 0)} پاسخ جعلی** در PCAP (`TTL={pdns.get('forged_ttls', [])}`)؛ از `{ds['domains_probed']}` دامنه، `{ds['total_dns_blocked']}` مورد دستکاری (`{ds['sinkhole_10_10_34_x']}` سینک‌هول، `{ds['forced_safesearch_216_239_38_120']}` SafeSearch اجباری، `{ds['private_rfc1918_redirect']}` RFC1918)؛ ربودن `{ds['ext_resolvers_hijacked']}/{ds['ext_resolvers_tested']}` Resolver خارجی (شامل `{ds['port_5353_hijacked']}` مورد روی پورت `5353`)؛ `HTTPS RR = {ds['isp_https_rr']}` | {ctl_dns_col_fa} | جعل پاسخ DNS در میانه مسیر با میانه `{fmt_num(pdns.get('forged_median_rtt_ms'), ' ms')}` در برابر `{fmt_num(pdns.get('clean_median_rtt_ms'), ' ms')}` پاسخ واقعی |
| **پروتکل‌های امن DNS (پورت ۸۵۳)** | `DoT TCP/853`: `{ps['dot_intl_isp_ok']}/{ps['dot_intl_total']}`؛ `DoH` دامنه‌ای: `{ps['doh_domain_isp_ok']}/{ps['doh_domain_total']}` (`{ps['doh_domain_isp_rst']}` Reset)؛ `DoQ UDP/853`: `{ps['doq_853_isp_ok']}/{ps['doq_853_total']}`؛ هم‌زمان `PortQuiz` روی `{ps['tcp_ports_isp_ok']}/{ps['tcp_ports_total']}` پورت باز است | {ctl_proto_col_fa} | انسداد هدفمند پروتکل‌های حریم خصوصی و رمزنگاری استاندارد IETF با وجود باز بودن پورت کنترل |
| **تله SNI ساختگی روی دو سرور آلمان** | از `{syn['total']}` دامنه غیرموجود `probe-test-404.*` به `Hetzner` و `Vultr`: **{syn['isp_hetzner_rst']}/{syn['total']} روی Hetzner** و **{syn['isp_vultr_rst']}/{syn['total']} روی Vultr** با `TCP_RST_INJECTED` قطع شدند (`{syn['isp_http_blockpage']}` صفحه فیلتر روی HTTP 80)؛ الگوهای قطع‌شده: {blocked_syn_str} | الگوهای آزاد ({clean_syn_str}) با `TLS_SERVER_HELLO` عبور کردند | **ابطال کامل بهانه تحریم خارجی یا خرابی سایت**: با وجود نبودِ میزبان واقعی، تجهیز میانی اپراتور ارتباط را قطع کرد |
| **تفکیک تحریم خارجی از فیلتر داخلی** | سایت‌هایی مانند {geo_str} هندشیک `TLS_SERVER_HELLO` را کامل می‌کنند و پس از آن خود سرور مقصد `403/421` می‌دهد؛ در مقابل `{dpi_s['sni_rst_count']}` دامنه با `TCP RST` میانی و `{dpi_s['tcp_tls_timeout_count']}` دامنه با Timeout/Drop متوقف شدند | مقایسه مستقیم با مقصد واقعی | جداسازی دقیق میان محدودیت مقصد خارجی و مداخله شبکه داخلی |
| **جرم‌شناسی زمانی و TTL در PCAP** | **{rst.get('n_events', 0)} رویداد DPI RST**؛ امضای غالب `TTL={dom_ttl}` در **{dom_n} مورد ({dom_pct}%)**؛ `{rst.get('n_early_rst', 0)}` مورد ورود پیش از `SYN-ACK RTT` سرور؛ میانه `RST = {fmt_num(rst.get('median_rst_delay_ms'), ' ms')}` مقابل `Server RTT = {fmt_num(rst.get('median_server_rtt_ms'), ' ms')}` (`p = {pval_str}`) | بدون تزریق RST میانی | اثبات فیزیکی صدور بسته جعلی `TCP RST` پیش از رسیدن پاسخ واقعی از سرور مقصد |
| **دور زدن پارسر با شکست ۲ بایتی (`split_2b`)** | تقسیم `ClientHello` در بایت ۲ منجر به دریافت `TLS_SERVER_HELLO` واقعی در: {split2b_str} | ارتباط مستقیم | نشان‌دهنده کارکرد اسکنر کم‌عمق SNI روی بسته اول `ClientHello` |
| **زیرساخت ابری و حلقه‌های مسیریابی** | **{cs['isp_disrupted']}/{cs['total_endpoints']} ({cs['disrupted_pct']}%) اندپوینت ابری مختل**؛ وضعیت MTR: {loop_fa} | {ctl_cloud_col_fa} | آسیب مستقیم به سرویس‌های ابری، مخازن کد، CDNها و سرویس‌های زیرساختی مجاز |
| **سرعت پایه، جیتر محلی و قفل مسیر** | بیشینه سرعت دانلود: **`{ss['max_isp_mbps']} Mbps`** (`{ss['max_isp_label']}`)؛ جیتر محلی گیت‌وی: `{fmt_num(ss['local_gw_jitter_ms'], ' ms')}` (`{ss['local_gw_loss_pct']}% Loss`)، `PMTU = {fmt_num(ps['pmtu_isp_bytes'], ' B')}`؛ مقاصد دارای افت/قطع: {stalled_str}؛ {fastly_note_fa} | سنجش هم‌زمان با بنچمارک کنترل | خط محلی کاربر کاملاً سالم است و افت سرعت صرفاً به‌صورت گزینشی یا بر اثر نقص مسیریابی رخ می‌دهد |

---

## ۲. ضمایم نموداری و مدارک

- [`01_dns_layers_and_resolver_hijack.png`](charts/01_dns_layers_and_resolver_hijack.png)
- [`02_dual_synthetic_sni_and_geoblock.png`](charts/02_dual_synthetic_sni_and_geoblock.png)
- [`03_pcap_rst_ttl_timing_and_evasion.png`](charts/03_pcap_rst_ttl_timing_and_evasion.png)
- [`04_cloud_infra_57_matrix_and_loops.png`](charts/04_cloud_infra_57_matrix_and_loops.png)
- [`05_protocols_dot_doh_doq_ports.png`](charts/05_protocols_dot_doh_doq_ports.png)
- [`06_throughput_and_fastly_mss_threshold.png`](charts/06_throughput_and_fastly_mss_threshold.png)
- [`07_jitter_burst_and_summary.png`](charts/07_jitter_burst_and_summary.png)
"""

    report_en = f"""# Comprehensive Technical Network Forensics & QoS Audit Report: {op['name_en']} ({meta['asn']})

- **Generated by**: `{APP_NAME} v{__version__}` (`{BRAND}` — `{AUTHOR}`)
- **Audit Timestamp (UTC)**: `{meta['timestamp_utc']}`
- **Audited Connection**: `{meta['connection_type']}` on `{meta['interface']}` (Mode: `{meta['mode']}`)
- **Audited ISP Public IP**: `{meta['isp_public_ip']}` (`{meta['asn']}`, Prefix `{meta['prefix']}`)
- **Control Clean IP**: `{ctl_ip_en}`

{history_section_en}## Key Forensic Findings
1. **DNS Tampering & Hijacking**: `{pdns.get('forged_count', 0)}` forged DNS packets captured (`TTL={pdns.get('forged_ttls', [])}`; forged median `{fmt_num(pdns.get('forged_median_rtt_ms'), ' ms')}` vs clean `{fmt_num(pdns.get('clean_median_rtt_ms'), ' ms')}`). Across `{ds['domains_probed']}` domains, `{ds['total_dns_blocked']}` were altered (`{ds['sinkhole_10_10_34_x']}` sinkhole, `{ds['forced_safesearch_216_239_38_120']}` forced SafeSearch, `{ds['private_rfc1918_redirect']}` RFC1918). External resolvers hijacked: `{ds['ext_resolvers_hijacked']}/{ds['ext_resolvers_tested']}` (port 5353 hijacks: `{ds['port_5353_hijacked']}`). `HTTPS/SVCB` records dropped from `{ds['control_https_rr']}` to `{ds['isp_https_rr']}`.
2. **Encrypted DNS Suppression**: DoT TCP/853 `{ps['dot_intl_isp_ok']}/{ps['dot_intl_total']}`, DoH domain `{ps['doh_domain_isp_ok']}/{ps['doh_domain_total']}`, DoQ UDP/853 `{ps['doq_853_isp_ok']}/{ps['doq_853_total']}`, while `{ps['tcp_ports_isp_ok']}/{ps['tcp_ports_total']}` PortQuiz TCP ports are reachable and PMTU is `{fmt_num(ps['pmtu_isp_bytes'], ' B')}`.
3. **Dual-Server Synthetic SNI Proof**: `{syn['isp_hetzner_rst']}/{syn['total']}` on Hetzner DE and `{syn['isp_vultr_rst']}/{syn['total']}` on Vultr DE triggered `TCP_RST_INJECTED` for non-existent `probe-test-404.*` domains (`{syn['isp_http_blockpage']}/{syn['total']}` HTTP blockpages on port 80), disproving remote-origin excuses.
4. **PCAP RST Timing & TTL Signature**: `{rst.get('n_events', 0)}` RST events captured (`TTL={dom_ttl}` in `{dom_n}` = `{dom_pct}%`, `{rst.get('n_early_rst', 0)}` arriving faster than server SYN-ACK RTT; median RST `{fmt_num(rst.get('median_rst_delay_ms'), ' ms')}` vs server RTT `{fmt_num(rst.get('median_server_rtt_ms'), ' ms')}`, Mann-Whitney `p = {pval_str}`).
5. **Cloud Infrastructure & Routing Loops**: `{cs['isp_disrupted']}/{cs['total_endpoints']}` (`{cs['disrupted_pct']}%`) cloud/dev endpoints disrupted. MTR trace analysis: {loop_en}.
6. **Baseline Bandwidth, Local Jitter & Thresholds**: Peak download `{ss['max_isp_mbps']} Mbps` (`{ss['max_isp_label']}`), local gateway jitter `{fmt_num(ss['local_gw_jitter_ms'], ' ms')}` (`{ss['local_gw_loss_pct']}%` loss), {fastly_note_en}.
"""

    (base_dir / "REPORT_FA.md").write_text(report_fa, encoding="utf-8")
    (base_dir / "REPORT_EN.md").write_text(report_en, encoding="utf-8")
    (raw_dir / "07_aggregated_metrics.json").write_text(json.dumps(agg, indent=2, ensure_ascii=False), encoding="utf-8")


def build_manifest_and_hashes(base_dir):
    manifest = {"generator": f"{APP_NAME} v{__version__} ({BRAND})", "files": []}
    hash_lines = []
    for sub in ("raw_data", "raw_pcaps", "charts"):
        folder = base_dir / sub
        if not folder.exists():
            continue
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                rel = path.relative_to(base_dir).as_posix()
                manifest["files"].append({"path": rel, "bytes": path.stat().st_size, "sha256": digest})
                hash_lines.append(f"{digest}  {rel}")
    for md in ("REPORT_FA.md", "REPORT_EN.md"):
        p = base_dir / md
        if p.exists():
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            manifest["files"].append({"path": md, "bytes": p.stat().st_size, "sha256": digest})
            hash_lines.append(f"{digest}  {md}")

    (base_dir / "EVIDENCE_MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    (base_dir / "SHA256SUMS.txt").write_text("\n".join(hash_lines) + "\n", encoding="utf-8")

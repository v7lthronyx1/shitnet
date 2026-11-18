import hashlib
import json
import re
import shutil
import subprocess
import weasyprint
from . import APP_NAME, AUTHOR, BRAND, __version__, font_face_css
from .analytics import fmt_num, fmt_pval


def ltr(text):
    return f'<span class="ltr" dir="ltr">\u2066{text}\u2069</span>'


def code_ltr(text, wrap=False):
    cls = "ltr wrap" if wrap else "ltr"
    return f'<code class="{cls}" dir="ltr">\u2066{text}\u2069</code>'


def common_css(title_hdr, right_hdr):
    return f"""{font_face_css()}
@page {{
  size: A4;
  margin: 15mm 12.5mm 14mm 12.5mm;
  @top-right {{
    content: "{title_hdr}";
    font-family: "Vazirmatn FD", "Vazirmatn", sans-serif;
    font-size: 7.3pt;
    color: #475569;
    border-bottom: 0.6pt solid #cbd5e1;
    padding-bottom: 3pt;
    margin-bottom: 4pt;
    vertical-align: bottom;
  }}
  @top-center {{
    content: "";
    border-bottom: 0.6pt solid #cbd5e1;
    padding-bottom: 3pt;
    margin-bottom: 4pt;
  }}
  @top-left {{
    content: "{right_hdr}";
    font-family: "JetBrains Mono", "Vazirmatn", monospace;
    font-size: 7.1pt;
    color: #475569;
    border-bottom: 0.6pt solid #cbd5e1;
    padding-bottom: 3pt;
    margin-bottom: 4pt;
    vertical-align: bottom;
    white-space: nowrap;
  }}
  @bottom-center {{
    content: "صفحه " counter(page) " از " counter(pages) "  |  {APP_NAME} ({BRAND})";
    font-family: "Vazirmatn FD", "Vazirmatn", sans-serif;
    font-size: 7.9pt;
    color: #334155;
    border-top: 0.5pt solid #e2e8f0;
    padding-top: 3pt;
  }}
}}
@page :first {{
  margin: 10mm 12.5mm 12.5mm 12.5mm;
  @top-right {{ content: none; border: none; }}
  @top-center {{ content: none; border: none; }}
  @top-left {{ content: none; border: none; }}
  @bottom-center {{ content: none; border: none; }}
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: "Vazirmatn FD", "Vazirmatn", sans-serif;
  direction: rtl;
  text-align: right;
  color: #1e293b;
  font-size: 8.75pt;
  line-height: 1.58;
  margin: 0;
  padding: 0;
}}
.ltr {{
  direction: ltr;
  unicode-bidi: isolate;
  font-family: "Vazirmatn", "DejaVu Sans", sans-serif;
}}
code.ltr {{
  direction: ltr;
  unicode-bidi: isolate;
  font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
  font-size: 7.5pt;
  background: #f1f5f9;
  color: #0f172a;
  border-radius: 2.5pt;
  padding: 0.5pt 3pt;
  white-space: nowrap;
}}
code.ltr.wrap {{ white-space: normal; word-break: break-word; overflow-wrap: anywhere; }}
.cover-banner {{
  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 68%, #7f1d1d 100%);
  color: #ffffff;
  border-radius: 7pt;
  padding: 12pt 14pt 10pt 14pt;
  margin-bottom: 8pt;
  border-bottom: 3.5pt solid #b91c1c;
}}
.cover-kicker {{ font-size: 7.8pt; color: #cbd5e1; margin-bottom: 4pt; }}
.cover-title {{ font-size: 13.6pt; font-weight: 800; line-height: 1.44; margin: 0 0 5pt 0; color: #ffffff; }}
.cover-subtitle {{ font-size: 8.5pt; line-height: 1.55; color: #e2e8f0; margin: 0; }}
.kpi-table {{
  width: 100%;
  border-collapse: separate;
  border-spacing: 5pt 0;
  margin: 6pt -5pt 8pt -5pt;
  break-inside: avoid;
}}
.kpi-cell {{
  width: 25%;
  background: #f8fafc;
  border: 0.7pt solid #cbd5e1;
  border-top: 3pt solid #1e3a5f;
  border-radius: 5pt;
  padding: 5pt 4.5pt;
  text-align: center;
  vertical-align: middle;
}}
.kpi-cell.red {{ border-top-color: #b91c1c; background: #fef2f2; }}
.kpi-cell.amber {{ border-top-color: #d97706; background: #fffbeb; }}
.kpi-cell.blue {{ border-top-color: #0284c7; background: #f0f9ff; }}
.kpi-val {{ font-size: 10.6pt; font-weight: 800; color: #0f172a; line-height: 1.28; }}
.kpi-lbl {{ font-size: 7.2pt; color: #475569; margin-top: 2pt; line-height: 1.32; }}
h2 {{
  font-size: 10.6pt;
  font-weight: 800;
  color: #0f172a;
  border-right: 3.5pt solid #b91c1c;
  padding: 3pt 8pt;
  background: #f8fafc;
  margin: 9pt 0 5pt 0;
  break-after: avoid;
}}
h2.blue {{ border-right-color: #0284c7; }}
p {{ margin: 0 0 5pt 0; }}
ul, ol {{ margin: 0 0 5.5pt 0; padding-right: 15pt; }}
li {{ margin-bottom: 2.5pt; }}
table.data {{
  width: 100%;
  table-layout: fixed;
  border-collapse: collapse;
  margin: 4.5pt 0 7.5pt 0;
  font-size: 7.6pt;
  line-height: 1.42;
}}
table.data th {{
  background: #0f172a;
  color: #ffffff;
  font-weight: 700;
  padding: 4pt 5pt;
  border: 0.6pt solid #334155;
  text-align: right;
  word-wrap: break-word;
}}
table.data td {{
  padding: 3.8pt 5pt;
  border: 0.6pt solid #cbd5e1;
  vertical-align: top;
  word-wrap: break-word;
  overflow-wrap: break-word;
}}
table.data tr:nth-child(even) td {{ background: #f8fafc; }}
table.data tr {{ break-inside: avoid; }}
.badge {{
  display: inline-block;
  font-size: 7.0pt;
  font-weight: 700;
  border-radius: 3pt;
  padding: 1pt 4pt;
  white-space: nowrap;
}}
.badge.red {{ background: #fee2e2; color: #991b1b; border: 0.5pt solid #fca5a5; }}
.badge.green {{ background: #dcfce7; color: #166534; border: 0.5pt solid #86efac; }}
.badge.blue {{ background: #e0f2fe; color: #075985; border: 0.5pt solid #7dd3fc; }}
.callout {{
  border: 0.8pt solid #cbd5e1;
  border-right: 3.5pt solid #0284c7;
  background: #f8fafc;
  border-radius: 4.5pt;
  padding: 6.5pt 9pt;
  margin: 5.5pt 0 7pt 0;
  break-inside: avoid;
}}
.callout.red {{ border-right-color: #b91c1c; background: #fef2f2; border-color: #fecaca; }}
.callout.blue {{ border-right-color: #0284c7; background: #f0f9ff; border-color: #bae6fd; }}
.callout.green {{ border-right-color: #15803d; background: #f0fdf4; border-color: #bbf7d0; }}
.fig-box {{
  border: 0.7pt solid #cbd5e1;
  border-radius: 5pt;
  padding: 4.5pt;
  margin: 5pt 0 7pt 0;
  background: #ffffff;
  text-align: center;
  break-inside: avoid;
}}
.fig-box img {{
  width: 97%;
  max-height: 75mm;
  height: auto;
  display: block;
  margin: 0 auto 3pt auto;
}}
.fig-cap {{
  font-size: 7.5pt;
  color: #334155;
  text-align: right;
  line-height: 1.42;
  padding: 1.5pt 4pt;
}}
.copy-box {{
  background: #f8fafc;
  border: 0.8pt solid #94a3b8;
  border-right: 3.5pt solid #1e3a5f;
  border-radius: 4.5pt;
  padding: 6.5pt 9pt;
  margin: 4.5pt 0 7pt 0;
  font-size: 8.0pt;
  line-height: 1.55;
}}
.copy-box p {{ margin: 0 0 3.5pt 0; }}
.copy-box p:last-child {{ margin-bottom: 0; }}
.page-break {{ page-break-before: always; }}
"""


def short_dot_err(err_text):
    s = str(err_text or "")
    if "ConnectionResetError" in s:
        return "TCP RST (Errno 104)"
    if "WRONG_VERSION_NUMBER" in s:
        return "SSL WrongVersion (Banner)"
    if "_ssl.c" in s or "handshake" in s:
        return "TLS Handshake Timeout"
    if "timed out" in s:
        return "TimeoutError"
    return s[:28]


def _loop_text(agg):
    loops = [m for m in agg["cloud_summary"].get("mtr_loop_summary", []) if m["has_loop"]]
    if not loops:
        return "در این ممیزی حلقه تا هاپ ۳۰ در MTR ثبت نشد"
    items = []
    for m in loops[:3]:
        ips = " / ".join(m["loop_ips"][:3]) if m["loop_ips"] else "TTL=30"
        items.append(f"{m['label']} ({m['ip']}) درون {ips} تا هاپ {m['max_hop']} ({m['last_loss_pct']:.0f}% loss / {m['worst_ms']} ms)")
    return "؛ ".join(items)


def build_ready_texts(agg):
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
    fastly_r = agg["pcap_fastly_tcp"].get("server_retransmissions", 0)

    ts_short = meta["timestamp_utc"][:19].replace("T", " ") + " UTC"
    pval_str = fmt_pval(rst.get("mannwhitney_u_less_pvalue"))
    dom_ttl = rst.get("dominant_rst_ttl")
    dom_n = rst.get("n_dominant_ttl", 0)
    dom_pct = rst.get("dominant_ttl_share_pct", 0.0)
    loop_txt = _loop_text(agg)
    blocked_syn = "، ".join(syn["blocked_patterns"][:5]) or "الگوهای فیلترشده"
    geo_ex = "، ".join(dpi_s["geo_isp_only_403_hosts"][:5]) or "سایت‌های تحریم خارجی"
    stalled_ex = "، ".join(ss["stalled_labels"][:4]) or "ندارد"
    fastly_line = (
        f"مسیر 151.101.18.132 (Fastly / deb.debian.org) سر بایت {fastly_s['stall_bytes']:,} با {fastly_r} بار Retransmission قفل می‌شود."
        if fastly_s["stalled"]
        else f"سرعت مسیرهای دانلود با حداکثر {ss['max_isp_mbps']} Mbps روی {ss['max_isp_label']} و مقاصد افت‌کرده: {stalled_ex}."
    )

    hist = agg.get("history_comparison") or []
    hist_clause = ""
    if len(hist) >= 2:
        prev_ips = "، ".join(h["ip"] for h in hist if h["ip"])
        prev_rsts = " -> ".join(str(h["rst_events"]) for h in hist)
        prev_cld = " -> ".join(f"{h['cloud_fail_pct']}%" for h in hist)
        hist_clause = f" تکرار آزمون در {len(hist)} نشست ({prev_ips}) نشان می‌دهد روند تزریق RST ({prev_rsts}) و اختلال کلودها ({prev_cld}) تداوم یا تشدید داشته است."

    op_support = (
        f"موضوع: درخواست ارجاع فوری به تیم مهندسی هسته (NOC) بابت اختلالات سطح بسته در شبکه {op['name_fa']} ({meta['asn']})\n"
        f"با سلام؛ اینجانب مشترک سرویس {op['service_type_fa']} (مشخصات خط: [شماره خط / اشتراک]، کد پیگیری قبلی در صورت وجود: [...]) هستم.\n"
        f"در تاریخ {ts_short} روی اتصال {meta['connection_type']} ({meta['interface']} با آی‌پی عمومی {meta['isp_public_ip']} در رنج {meta['prefix']}) ممیزی فنی شبکه اجرا شده که نشان می‌دهد خط محلی کاربر کاملاً سالم است (جیتر گیت‌وی {fmt_num(ss['local_gw_jitter_ms'], ' ms')}، اتلاف محلی {ss['local_gw_loss_pct']}%، PMTU {fmt_num(ps['pmtu_isp_bytes'], ' B')} و بیشینه سرعت پایه {ss['max_isp_mbps']} Mbps روی {ss['max_isp_label']})\n"
        f"اما در شبکه اپراتور موارد زیر رخ می‌دهد:\n"
        f"1) اختلال {cs['isp_disrupted']} از {cs['total_endpoints']} اندپوینت ابری و توسعه‌ای مجاز ({cs['disrupted_pct']}%). وضعیت MTR: {loop_txt}.\n"
        f"2) {fastly_line} مقاصد دارای افت یا تایم‌اوت: {stalled_ex}.\n"
        f"3) ثبت {rst.get('n_events', 0)} بسته جعلی TCP RST در PCAP (تعداد {dom_n} مورد با TTL={dom_ttl} معادل {dom_pct}%؛ میانه {fmt_num(rst.get('median_rst_delay_ms'), ' ms')} مقابل {fmt_num(rst.get('median_server_rtt_ms'), ' ms')} سرور با p={pval_str}) و قطع {syn['isp_hetzner_rst']}/{syn['total']} نام ساختگی روی Hetzner و {syn['isp_vultr_rst']}/{syn['total']} روی Vultr.\n"
        f"4) تزریق {pdns.get('forged_count', 0)} پاسخ DNS جعلی روی پورت ۵۳/۵۳۵۳ و انسداد DoT TCP/853 ({ps['dot_intl_isp_ok']}/{ps['dot_intl_total']})، DoH ({ps['doh_domain_isp_ok']}/{ps['doh_domain_total']}) و DoQ UDP/853 ({ps['doq_853_isp_ok']}/{ps['doq_853_total']}) با وجود باز بودن portquiz:853 ({ps['tcp_ports_isp_ok']}/{ps['tcp_ports_total']} پورت باز).{hist_clause}\n"
        f"لطفاً تیکت بدون پاسخ کلیشه‌ای به تیم فنی NOC ارجاع و نتیجه مکتوب جهت ثبت در سامانه ۱۹۵ اعلام گردد."
    )

    cra_195 = (
        f"موضوع: شکایت فنی علیه {op['legal_fa']} ({meta['asn']}) بابت اختلال زیرساخت‌های مجاز ابری، تزریق جعلی بسته و افت کیفیت سرویس\n"
        f"با سلام؛ اینجانب مشترک {op['service_type_fa']} (شماره خط/اشتراک: [شماره]، کد پیگیری پشتیبانی {op['support_code']}: [...])، مستند به ممیزی سطح بسته (PCAPNG با امضای SHA-256) اجراشده در تاریخ {ts_short} روی آی‌پی عمومی {meta['isp_public_ip']} ({meta['asn']}):\n"
        f"۱. سلامت کامل سمت کاربر و تمایز با تحریم خارجی: جیتر محلی تنها {fmt_num(ss['local_gw_jitter_ms'], ' ms')}، PMTU برابر {fmt_num(ps['pmtu_isp_bytes'], ' B')} و سرعت دانلود پایه تا {ss['max_isp_mbps']} Mbps ({ss['max_isp_label']}) است. علاوه بر این، سایت‌های دارای تحریم خارجی ({geo_ex}) پس از هندشیک سالم TLS خودشان کد 403 می‌دهند؛ در حالی که ارسال {syn['total']} نام ساختگی غیرموجود (probe-test-404.*) به دو سرور آزمایشی در آلمان منجر به قطع {syn['isp_hetzner_rst']}/{syn['total']} روی Hetzner و {syn['isp_vultr_rst']}/{syn['total']} روی Vultr (مانند {blocked_syn}) توسط میانی شبکه اپراتور شد.\n"
        f"۲. اثبات ریاضی تزریق TCP RST در PCAP: ثبت {rst.get('n_events', 0)} رویداد RST پیش از RTT سرور (میانه {fmt_num(rst.get('median_rst_delay_ms'), ' ms')} مقابل {fmt_num(rst.get('median_server_rtt_ms'), ' ms')}، Mann-Whitney p={pval_str}) با {dom_pct}% امضای تکرارشونده TTL={dom_ttl}.\n"
        f"۳. آسیب به سرویس‌های ابری و مسیریابی: اختلال {cs['isp_disrupted']}/{cs['total_endpoints']} ({cs['disrupted_pct']}%) اندپوینت ابری و توسعه‌ای؛ {loop_txt}؛ {fastly_line}\n"
        f"۴. دستکاری DNS و قطع استانداردهای امنیتی: {pdns.get('forged_count', 0)} پاسخ DNS جعلی، حذف رکوردهای HTTPS/SVCB (از {ds['control_https_rr']} به {ds['isp_https_rr']}) و قطع DoT ({ps['dot_intl_isp_ok']}/{ps['dot_intl_total']}) و DoQ UDP/853 ({ps['doq_853_isp_ok']}/{ps['doq_853_total']}) با وجود باز بودن portquiz:853.{hist_clause}\n"
        f"تقاضای رسیدگی کارشناسی، الزام اپراتور به رفع اختلال مسیرها و زیرساخت‌های مجاز و اعلام پاسخ مکتوب را دارم."
    )

    tazirat_135 = (
        f"موضوع: شکایت حقوق مصرف‌کننده علیه {op['legal_fa']} ({meta['asn']}) بابت کم‌فروشی فنی و عدم ایفای تعهدات سرویس اینترنت بین‌الملل\n"
        f"ریاست محترم سازمان تعزیرات حکومتی / سامانه ۱۲۴؛ اینجانب [نام و نام خانوادگی]، کدملی [کد ملی]، مالک سرویس [شماره خط/اشتراک]، بهای کامل سرویس اینترنت بین‌الملل را پرداخت کرده‌ام؛ لکن فروشنده بدون درج در قرارداد، {cs['disrupted_pct']}% ({cs['isp_disrupted']} از {cs['total_endpoints']}) سرویس‌های ابری و زیرساختی مجاز، پروتکل‌های رمزنگاری DNS پورت ۸۵۳ و دسترسی مخازن نرم‌افزاری/دانلود ({stalled_ex}) را مختل کرده است، در حالی که خطای محلی کاربر ۰% (جیتر {fmt_num(ss['local_gw_jitter_ms'], ' ms')}، سرعت پایه تا {ss['max_isp_mbps']} Mbps) است.{hist_clause}\n"
        f"خواهان الزام شرکت به تحویل کامل خدمات فروخته‌شده و جبران خسارت هستم."
    )

    divan_and_136 = (
        f"خلاصه گزارش ترک فعل نظارتی به سازمان بازرسی کل کشور (https://136.ir) و دیوان عدالت اداری (ثنا) — پس از بی‌پاسخی یا پاسخ غیرکارشناسی ۱۹۵:\n"
        f"خواهان: [مشخصات] | خوانده: سازمان تنظیم مقررات و ارتباطات رادیویی (مرجع ناظر پروانه {meta['asn']} - {op['legal_fa']})\n"
        f"مستندات خام PCAPNG دارای گواهی SHA-256 روی آی‌پی {meta['isp_public_ip']} نشان می‌دهد {cs['isp_disrupted']}/{cs['total_endpoints']} ({cs['disrupted_pct']}%) زیرساخت ابری مجاز مختل شده، {rst.get('n_events', 0)} بسته TCP RST پیش از سرور تزریق گردیده (p={pval_str}) و حتی {syn['isp_hetzner_rst']}/{syn['total']} دامنه غیرموجود روی سرورهای کنترل آلمان قطع شده‌اند.{hist_clause} خواستار رسیدگی کارشناسی و الزام به رفع ممانعت فنی غیرقانونی هستم."
    )

    return {
        "op_support": op_support,
        "cra_195": cra_195,
        "tazirat_135": tazirat_135,
        "divan_and_136": divan_and_136,
    }


def build_report_html(agg, d2, d4, d5, evidence_dir):
    charts_uri = (evidence_dir / "charts").resolve().as_uri()
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
    fastly_r = agg["pcap_fastly_tcp"].get("server_retransmissions", 0)
    pval_str = fmt_pval(rst.get("mannwhitney_u_less_pvalue"))
    dom_ttl = rst.get("dominant_rst_ttl")
    dom_n = rst.get("n_dominant_ttl", 0)
    dom_pct = rst.get("dominant_ttl_share_pct", 0.0)

    sp_rows = ""
    for s in d5.get("speed_benchmarks", []):
        m_ok = s["isp"]["rc"] == 0 and s["isp"]["mbps"] >= 1.0
        badge = '<span class="badge green">سالم</span>' if m_ok else '<span class="badge red">افت/تایم‌اوت</span>'
        ctl = s.get("control") or {}
        ctl_str = f"{ltr(str(ctl['mbps']) + ' Mbps')} ({ltr(str(ctl['bytes']) + ' B')})" if ctl.get("mbps") is not None else "—"
        sp_rows += (
            f"<tr>"
            f"<td>{code_ltr(s['label'], True)}</td>"
            f"<td>{code_ltr(s['ip'])}</td>"
            f"<td>{ltr(str(s['isp']['mbps']) + ' Mbps')} ({ltr(str(s['isp']['bytes']) + ' B')} / rc={ltr(str(s['isp']['rc']))})</td>"
            f"<td>{ctl_str}</td>"
            f"<td>{badge}</td>"
            f"</tr>"
        )

    dot_rows = ""
    for r in d4.get("dot", []):
        if r["label"] == "Shecan":
            continue
        m_st = "پاسخ سالم" if r["isp"]["dns_ok"] else short_dot_err(r["isp"].get("err"))
        ctl = r.get("control") or {}
        v_st = ("سالم" if ctl.get("dns_ok") else short_dot_err(ctl.get("err"))) if meta["has_control"] else "DirectOnly"
        if not r["isp"]["dns_ok"] and (not meta["has_control"] or ctl.get("dns_ok")):
            b = f'<span class="badge red">مسدود روی {op["short_en"]}</span>'
        elif r["label"] == "Control-Port853-EC2":
            b = '<span class="badge blue">کنترل باز</span>'
        else:
            b = '<span class="badge green">سالم</span>'
        dot_rows += f"<tr><td>{code_ltr(r['label'], True)}</td><td>{code_ltr(r['ip'] + ':853')}</td><td>{code_ltr(m_st, True)}</td><td>{ltr(v_st)}</td><td>{b}</td></tr>"

    synth_examples = []
    for s in d2.get("synthetic_sni_probes", []):
        if s["isp_hetzner"]["outcome"] == "TCP_RST_INJECTED" or s["isp_vultr"]["outcome"] == "TCP_RST_INJECTED":
            hp = (s.get("isp_http_host_hetzner") or {}).get("block_sig") or (s.get("isp_http_host_hetzner") or {}).get("status") or "—"
            synth_examples.append(
                f"<tr><td>{code_ltr(s['synthetic_sni'], True)}</td>"
                f"<td><span class='badge red'>{ltr(s['isp_hetzner']['outcome'])}</span></td>"
                f"<td><span class='badge red'>{ltr(s['isp_vultr']['outcome'])}</span></td>"
                f"<td><span class='badge blue'>{ltr(str(hp))}</span></td></tr>"
            )
    synth_rows_html = "\n".join(synth_examples[:10]) or "<tr><td colspan='4'>مورد مسدودشده‌ای در SNI ساختگی ثبت نشد</td></tr>"

    hist_block = ""
    hist = agg.get("history_comparison") or []
    if len(hist) >= 2:
        h_rows = "\n".join(
            f"<tr><td>{ltr(h['label'])}</td><td>{code_ltr(h['ip'])}</td><td>{ltr(str(h['rst_events']))} ({ltr(str(h['dominant_ttl_share_pct']) + '%')})</td><td>{ltr(str(h['cloud_fail_count']) + '/' + str(h['cloud_total']))} ({ltr(str(h['cloud_fail_pct']) + '%')})</td><td>{ltr(str(h['dns_sinkholes']))}</td></tr>"
            for h in hist
        )
        hist_block = f"""
<h2>مقایسه با نشست‌های قبلی</h2>
<table class="data">
  <thead><tr><th>نشست / تاریخ</th><th>آی‌پی عمومی</th><th>تزریق RST</th><th>اختلال کلودها</th><th>Sinkhole DNS</th></tr></thead>
  <tbody>{h_rows}</tbody>
</table>"""

    css = common_css(
        f"گزارش فنی-حقوقی شبکه {op['name_fa']} ({meta['asn']})",
        f"{APP_NAME} v{__version__} | {meta['asn']} | {meta['isp_public_ip']} | {meta['timestamp_utc'][:10]}",
    )

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head><meta charset="utf-8"><title>گزارش فنی و حقوقی {op['name_fa']} ({meta['asn']}) — {APP_NAME}</title><style>{css}</style></head>
<body>
<div class="cover-banner">
  <div class="cover-kicker">گزارش مستند جرم‌شناسی شبکه و کیفیت سرویس | {ltr(APP_NAME + ' v' + __version__ + ' • ' + BRAND + ' (' + AUTHOR + ')')}</div>
  <h1 class="cover-title">گزارش کارشناسی فنی و حقوقی اختلالات شبکه {op['legal_fa']} ({ltr(meta['asn'])})</h1>
  <p class="cover-subtitle">
    این ممیزی در تاریخ {code_ltr(meta['timestamp_utc'][:19].replace('T', ' ') + ' UTC')} روی اتصال {code_ltr(meta['connection_type'])} ({code_ltr(meta['interface'])} با آی‌پی عمومی {code_ltr(meta['isp_public_ip'])} از پیشوند {code_ltr(meta['prefix'])}) در حالت {code_ltr(meta['mode'])} اجرا شده و شامل مدارک خام {ltr('PCAPNG')} با امضای {ltr('SHA-256')} است.
  </p>
</div>

<table class="kpi-table">
  <tr>
    <td class="kpi-cell red">
      <div class="kpi-val">{ltr(str(rst.get('n_events', 0)))} ({ltr(pval_str)})</div>
      <div class="kpi-lbl">تزریق {ltr('RST')} در PCAP؛ سهم {ltr('TTL=' + str(dom_ttl))}: {ltr(str(dom_n))} ({ltr(str(dom_pct) + '%')})</div>
    </td>
    <td class="kpi-cell amber">
      <div class="kpi-val">{ltr(str(syn['isp_hetzner_rst']) + ' / ' + str(syn['total']))} دو-سروره</div>
      <div class="kpi-lbl">قطع دامنه‌های ساختگی {code_ltr('probe-test-404.*')} روی {ltr('Hetzner')} و {ltr('Vultr')}</div>
    </td>
    <td class="kpi-cell red">
      <div class="kpi-val">{ltr(str(cs['isp_disrupted']) + ' / ' + str(cs['total_endpoints']))} ({ltr(str(cs['disrupted_pct']) + '%')})</div>
      <div class="kpi-lbl">اختلال سرویس‌های ابری و توسعه‌ای روی {op['name_fa']}</div>
    </td>
    <td class="kpi-cell blue">
      <div class="kpi-val">{ltr(str(pdns.get('forged_count', 0)))} جعل DNS / {ltr(str(ps['dot_intl_isp_ok']) + '/' + str(ps['dot_intl_total']))} DoT</div>
      <div class="kpi-lbl">ربایش Resolver خارجی ({ltr(str(ds['ext_resolvers_hijacked']) + '/' + str(ds['ext_resolvers_tested']))}) و وضع پورت {ltr('853')}</div>
    </td>
  </tr>
</table>

<div class="callout red">
  <strong>اثبات سلامت سمت کاربر:</strong>
  جیتر گیت‌وی محلی ({code_ltr(meta['gw_ip'])}) تنها {code_ltr(fmt_num(ss['local_gw_jitter_ms'], ' ms'))} با {ltr(str(ss['local_gw_loss_pct']) + '% Loss')}، {code_ltr('PMTU = ' + fmt_num(ps['pmtu_isp_bytes'], ' B'))} و بیشینه سرعت دانلود پایه تا {code_ltr(str(ss['max_isp_mbps']) + ' Mbps')} ({code_ltr(ss['max_isp_label'])}) ثبت شده است.
</div>

{hist_block}

<h2>۱. جرم‌یابی {ltr('DNS')} و انسداد پروتکل‌های امن ({ltr('DoT / DoH / DoQ')})</h2>
<p>
  در بسته‌های ضبط‌شده، <strong>{ltr(str(pdns.get('forged_count', 0)))} پاسخ جعلی DNS</strong> با {code_ltr('TTL=' + str(pdns.get('forged_ttls', [])))} و میانه {code_ltr(fmt_num(pdns.get('forged_median_rtt_ms'), ' ms'))} (در برابر {code_ltr(fmt_num(pdns.get('clean_median_rtt_ms'), ' ms'))} پاسخ سالم) کشف شد. از {ltr(str(ds['domains_probed']))} دامنه تست‌شده، {ltr(str(ds['total_dns_blocked']))} دامنه تغییر مسیر یافتند و از {ltr(str(ds['ext_resolvers_tested']))} Resolver خارجی، {ltr(str(ds['ext_resolvers_hijacked']))} مورد ربوده شدند (شامل {ltr(str(ds['port_5353_hijacked']))} مورد روی پورت غیرمتعارف {ltr('5353')}).
</p>

<div class="fig-box">
  <img src="{charts_uri}/01_dns_layers_and_resolver_hijack.png" alt="نمودار DNS">
  <div class="fig-cap"><strong>شکل ۱:</strong> تفکیک لایه‌های فیلترینگ در {ltr(str(ds['domains_probed']))} دامنه و مکانیزم‌های ربایش DNS و تضعیف {ltr('HTTPS RR / DNSSEC')}.</div>
</div>

<table class="data">
  <thead><tr><th>سرویس DNS رمزنگاری‌شده</th><th>پروتکل</th><th>وضعیت روی {op['name_fa']}</th><th>وضعیت کنترل</th><th>نتیجه</th></tr></thead>
  <tbody>{dot_rows}</tbody>
</table>

<h2>۲. آزمایش دو-سروره ({ltr('Hetzner + Vultr')}) و تفکیک تحریم خارجی</h2>
<p>
  از <strong>{ltr(str(syn['total']))} نام ساختگی غیرموجود</strong> ({code_ltr('probe-test-404.<domain>')}) ارسالی به سرورهای آلمان، <strong>{ltr(str(syn['isp_hetzner_rst']) + '/' + str(syn['total']))}</strong> روی {ltr('Hetzner')} و <strong>{ltr(str(syn['isp_vultr_rst']) + '/' + str(syn['total']))}</strong> روی {ltr('Vultr')} با {code_ltr('TCP_RST_INJECTED')} قطع شدند. در مقابل سایت‌های دارای تحریم خارجی ({code_ltr(', '.join(dpi_s['geo_isp_only_403_hosts'][:6]) or 'N/A')}) هندشیک {ltr('TLS')} را کامل کرده و خود سرور کد ۴۰۳ داد.
</p>
<table class="data">
  <thead><tr><th>دامنه ساختگی (SNI ناموجود)</th><th>Hetzner DE</th><th>Vultr DE</th><th>HTTP 80</th></tr></thead>
  <tbody>{synth_rows_html}</tbody>
</table>

<div class="fig-box">
  <img src="{charts_uri}/02_dual_synthetic_sni_and_geoblock.png" alt="SNI ساختگی">
  <div class="fig-cap"><strong>شکل ۲:</strong> تله SNI ساختگی دو-سروره (چپ) و جداسازی تحریم خارجی از مداخله اپراتور (راست).</div>
</div>

<h2>۳. جرم‌یابی زمانی {ltr('PCAP')}، شکست ۲ بایتی، زیرساخت ابری و سرعت</h2>
<div class="fig-box">
  <img src="{charts_uri}/03_pcap_rst_ttl_timing_and_evasion.png" alt="توزیع زمانی RST">
  <div class="fig-cap"><strong>شکل ۳:</strong> مقایسه تاخیر بسته‌های {ltr('RST')} با {ltr('SYN-ACK RTT')} واقعی سرور ({code_ltr('p=' + pval_str)}) و ماتریس ۹ حالته فرار DPI.</div>
</div>

<p>
  از <strong>{ltr(str(cs['total_endpoints']))} اندپوینت ابری</strong>، <strong>{ltr(str(cs['isp_disrupted']))} مورد ({ltr(str(cs['disrupted_pct']) + '%')})</strong> مختل هستند. وضعیت MTR: {ltr(_loop_text(agg))}. بیشینه سرعت پایه {code_ltr(str(ss['max_isp_mbps']) + ' Mbps')} و وضعیت Fastly: {ltr('توقف در ' + str(fastly_s['stall_bytes']) + ' B (' + str(fastly_r) + ' Retrans)') if fastly_s['stalled'] else ltr('کامل (' + str(fastly_s['mbps']) + ' Mbps)')}.
</p>

<div class="fig-box">
  <img src="{charts_uri}/04_cloud_infra_57_matrix_and_loops.png" alt="زیرساخت ابری و MTR">
  <div class="fig-cap"><strong>شکل ۴:</strong> تفکیک اختلال سرویس‌های ابری و مسیرهای MTR.</div>
</div>

<table class="data">
  <thead><tr><th>مقصد دانلود</th><th>IP</th><th>سرعت {op['name_fa']}</th><th>سرعت کنترل</th><th>وضعیت</th></tr></thead>
  <tbody>{sp_rows}</tbody>
</table>

<div class="fig-box">
  <img src="{charts_uri}/06_throughput_and_fastly_mss_threshold.png" alt="سرعت و Fastly">
  <div class="fig-cap"><strong>شکل ۵:</strong> بنچمارک سرعت و آزمایش آستانه بایت روی Fastly.</div>
</div>

<div class="callout green">
  <strong>ضمایم و اصالت ({ltr('SHA-256')}):</strong> تمام داده‌های خام، فایل‌های {code_ltr('PCAPNG')} و نمودارها با هش یکتای {code_ltr('SHA256SUMS.txt')} و {code_ltr('PACKAGE_SHA256SUMS.txt')} پیوست شده‌اند.
</div>
</body>
</html>
"""


def build_guide_html(agg):
    meta = agg["session_meta"]
    op = meta["operator"]
    syn = agg["synthetic_sni"]
    rst = agg["pcap_dpi_rst"]
    pdns = agg["pcap_dns_hijack"]
    cs = agg["cloud_summary"]
    ps = agg["protocols_summary"]
    ss = agg["speed_summary"]
    fastly_s = agg["fastly_stall"]
    pval_str = fmt_pval(rst.get("mannwhitney_u_less_pvalue"))
    dom_ttl = rst.get("dominant_rst_ttl")
    dom_pct = rst.get("dominant_ttl_share_pct", 0.0)
    texts = build_ready_texts(agg)

    anti_excuse_rows = [
        ("«مشکل از آنتن، مودم یا گوشی/وای‌فای خودتان است»",
         f"ممیزی روی {code_ltr(meta['connection_type'])} با جیتر محلی تنها {code_ltr(fmt_num(ss['local_gw_jitter_ms'], ' ms'))} ({ltr(str(ss['local_gw_loss_pct']) + '% Loss')})، {code_ltr('PMTU=' + fmt_num(ps['pmtu_isp_bytes'], ' B'))} و سرعت پایه {code_ltr(str(ss['max_isp_mbps']) + ' Mbps')} روی {code_ltr(ss['max_isp_label'])} انجام شده است؛ لذا سمت کاربر کاملاً سالم است."),
        ("«سایت خارجی تحریم است یا پاسخ نمی‌دهد»",
         f"سایت‌های تحریمی واقعی هندشیک TLS را باز کرده و بعد خودشان کد ۴۰۳ می‌دهند؛ اما برای {ltr(str(syn['total']))} نام ساختگی غیرموجود روی {ltr('Hetzner')} و {ltr('Vultr')} آلمان، {ltr(str(syn['isp_hetzner_rst']))} مورد توسط تجهیزات میانی شما پیش از سرور قطع شدند."),
        ("«فقط شبکه‌های اجتماعی فیلتر هستند»",
         f"بحث سر شبکه‌های اجتماعی نیست؛ {ltr(str(cs['isp_disrupted']) + '/' + str(cs['total_endpoints']))} ({ltr(str(cs['disrupted_pct']) + '%')}) سرویس‌های ابری، مخازن کد، CDNها و پروتکل‌های امن پورت ۸۵۳ مختل شده‌اند."),
        ("«DNS را تغییر دهید درست می‌شود»",
         f"در {ltr('PCAP')}، {ltr(str(pdns.get('forged_count', 0)))} پاسخ جعلی روی Resolverهای خارجی ثبت شد و سرویس‌های رمزنگاری‌شده پورت ۸۵۳ ({ltr('DoT/DoQ')}) با وجود باز بودن {code_ltr('portquiz:853')} قطع هستند."),
    ]
    excuse_html = "\n".join(f"<tr><td><strong>{q}</strong></td><td>{a}</td></tr>" for q, a in anti_excuse_rows)

    def to_html_copy(txt):
        pat = re.compile(r"([A-Za-z0-9][A-Za-z0-9._:/+-]*(?:\s+[A-Za-z0-9][A-Za-z0-9._:/+-]*)*)")
        lines = []
        for para in txt.split("\n"):
            p = para.strip()
            if p:
                escaped = pat.sub(lambda m: ltr(m.group(1)) if re.search(r"[A-Za-z.=:/-]", m.group(1)) else m.group(1), p)
                lines.append(f"<p>{escaped}</p>")
        return "\n".join(lines)

    css = common_css(
        f"راهنمای دفاع تلفنی و متن شکایت | {op['name_fa']}",
        f"{APP_NAME} v{__version__} | {meta['asn']} | {meta['isp_public_ip']}",
    )
    fastly_bullet = (
        f"توقف مسیر Fastly ({code_ltr('151.101.18.132')}) سر {ltr(str(fastly_s['stall_bytes']) + ' B')}"
        if fastly_s["stalled"]
        else f"سرعت Fastly عادی ({ltr(str(fastly_s['mbps']) + ' Mbps')})"
    )

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head><meta charset="utf-8"><title>راهنمای دفاع تلفنی و متن شکایت {op['name_fa']} — {APP_NAME}</title><style>{css}</style></head>
<body>
<div class="cover-banner">
  <div class="cover-kicker">بسته عملیاتی شکایت رسمی | {ltr(APP_NAME + ' v' + __version__ + ' • ' + BRAND)}</div>
  <h1 class="cover-title">راهنمای دفاع تلفنی ({ltr(op['support_code'])}) و متن‌های شکایت {op['name_fa']} ({ltr(meta['asn'])})</h1>
  <p class="cover-subtitle">ماتریس ضدبهانه، خلاصه شواهد فنی ({code_ltr(meta['isp_public_ip'])}) و متن‌های آماده ثبت در پشتیبانی اپراتور، سامانه ۱۹۵، تعزیرات ۱۳۵/۱۲۴، سازمان بازرسی ۱۳۶ و ثنا.</p>
</div>

<h2>۱. خلاصه شواهد کلیدی قابل ارائه</h2>
<ul>
  <li><strong>تزریق بسته جعلی و امضای {ltr('TTL')}:</strong> {ltr(str(rst.get('n_events', 0)))} رویداد {ltr('RST')} ({ltr(str(dom_pct) + '% TTL=' + str(dom_ttl))}، احتمال تصادفی {code_ltr(pval_str)}) و قطع {ltr(str(syn['isp_hetzner_rst']) + '/' + str(syn['total']))} نام ساختگی.</li>
  <li><strong>زیرساخت ابری و سرعت:</strong> {ltr(str(cs['isp_disrupted']) + '/' + str(cs['total_endpoints']))} ({ltr(str(cs['disrupted_pct']) + '%')}) اندپوینت ابری مختل، جیتر محلی {code_ltr(fmt_num(ss['local_gw_jitter_ms'], ' ms'))}، بیشینه سرعت {code_ltr(str(ss['max_isp_mbps']) + ' Mbps')} و {fastly_bullet}.</li>
</ul>

<h2>۲. ماتریس ضدبهانه در مکالمه با پشتیبانی ({ltr(op['support_code'])})</h2>
<table class="data">
  <colgroup><col style="width: 31%;"><col style="width: 69%;"></colgroup>
  <thead><tr><th>بهانه احتمالی کارشناس</th><th>پاسخ فنی مستند شما</th></tr></thead>
  <tbody>{excuse_html}</tbody>
</table>

<div class="page-break"></div>
<h2>۳. متن آماده ثبت در پشتیبانی {op['name_fa']} ({ltr(op['support_tel'])})</h2>
<div class="copy-box">{to_html_copy(texts['op_support'])}</div>

<h2>۴. متن رسمی شکایت در سامانه ۱۹۵ رگولاتوری ({code_ltr('https://195.cra.ir')})</h2>
<div class="copy-box">{to_html_copy(texts['cra_195'])}</div>

<div class="page-break"></div>
<h2>۵. متن شکایت به سامانه ۱۲۴ و سازمان تعزیرات ({code_ltr('https://tazirat135.ir')})</h2>
<div class="copy-box">{to_html_copy(texts['tazirat_135'])}</div>

<h2>۶. متن دادخواست دیوان عدالت اداری (ثنا) و سازمان بازرسی ({code_ltr('https://136.ir')})</h2>
<div class="copy-box">{to_html_copy(texts['divan_and_136'])}</div>
</body>
</html>
"""


def _write_checksums(pkg_dir):
    sum_path = pkg_dir / "PACKAGE_SHA256SUMS.txt"
    if sum_path.exists():
        sum_path.unlink()
    lines = []
    for p in sorted(pkg_dir.rglob("*")):
        if p.is_dir() or p.name == "PACKAGE_SHA256SUMS.txt":
            continue
        rel = p.relative_to(pkg_dir).as_posix()
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{sha}  {rel}")
    sum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_complaint_package(audit_dir, agg, d2, d4, d5):
    meta = agg["session_meta"]
    op = meta["operator"]
    pkg_dir = audit_dir / "complaint_package"
    evidence_dir = pkg_dir / "evidence"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    for sub in ("charts", "raw_data", "raw_pcaps"):
        src = audit_dir / sub
        if src.exists():
            shutil.copytree(src, evidence_dir / sub)
    for fname in ("REPORT_FA.md", "REPORT_EN.md", "EVIDENCE_MANIFEST.json", "SHA256SUMS.txt"):
        src = audit_dir / fname
        if src.exists():
            shutil.copy2(src, evidence_dir / fname)

    texts = build_ready_texts(agg)
    ready_txt = "\n\n\n".join([
        f"=== ۱. متن ارجاع به NOC و پشتیبانی {op['name_fa']} ({op['support_channel']}) ===\n" + texts["op_support"],
        "=== ۲. متن رسمی شکایت در سامانه ۱۹۵ رگولاتوری (https://195.cra.ir) ===\n" + texts["cra_195"],
        "=== ۳. متن شکایت به سامانه ۱۲۴ و سازمان تعزیرات (https://tazirat135.ir) ===\n" + texts["tazirat_135"],
        "=== ۴. متن دادخواست دیوان عدالت اداری (ثنا) و گزارش سازمان بازرسی (https://136.ir) ===\n" + texts["divan_and_136"],
    ]) + "\n"
    (pkg_dir / "01_متن_آماده_ثبت_شکایت.txt").write_text(ready_txt, encoding="utf-8")

    prefix_name = f"{op['short_en']}_{meta['asn']}"
    report_pdf = pkg_dir / f"{prefix_name}_Legal_Technical_Report_FA.pdf"
    guide_pdf = pkg_dir / f"{prefix_name}_Complaint_Texts_And_Call_Guide_FA.pdf"

    guide_md = f"""# راهنمای ثبت و پیگیری شکایت {op['name_fa']} ({meta['asn']})

- **اپراتور**: {op['legal_fa']} (`{meta['asn']}`)
- **پشتیبانی اپراتور**: `{op['support_channel']}`
- **آی‌پی عمومی ممیزی**: `{meta['isp_public_ip']}` (`{meta['prefix']}`)

## مراحل پیگیری
1. ثبت تیکت یا تماس با پشتیبانی اپراتور ({op['support_tel']}) و دریافت کد پیگیری.
2. ثبت شکایت رسمی در `https://195.cra.ir` همراه با فایل `{report_pdf.name}` و آرشیو `evidence/`.
3. ثبت هم‌زمان در `https://tazirat135.ir` و سامانه `124` بابت کم‌فروشی فنی اینترنت بین‌الملل.
4. در صورت بی‌پاسخی یا بستن غیرکارشناسی تیکت ۱۹۵: پیگیری در `https://136.ir` و دیوان عدالت اداری (ثنا).
"""
    (pkg_dir / "00_راهنمای_مراجع_شکایت.md").write_text(guide_md, encoding="utf-8")

    weasyprint.HTML(string=build_report_html(agg, d2, d4, d5, evidence_dir), base_url=str(pkg_dir)).write_pdf(str(report_pdf))
    weasyprint.HTML(string=build_guide_html(agg), base_url=str(pkg_dir)).write_pdf(str(guide_pdf))
    _write_checksums(pkg_dir)

    return {
        "pkg_dir": str(pkg_dir),
        "report_pdf": str(report_pdf),
        "guide_pdf": str(guide_pdf),
    }

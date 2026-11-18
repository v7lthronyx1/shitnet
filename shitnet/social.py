import getpass
import pathlib
import shutil
import socket
import subprocess
import tempfile
import matplotlib.pyplot as plt
import weasyprint
from PIL import Image
from . import APP_NAME, BRAND, FONTS_DIR, __version__, font_face_css
from .analytics import fmt_num, fmt_pval
from .charts import (
    plot_cloud_matrix_ax,
    plot_history_or_impact_ax,
    plot_pcap_rst_hist_ax,
    plot_protocols_ax,
    plot_speed_ax,
    plot_synthetic_sni_ax,
    setup_mpl_style,
)


def ltr(text):
    return f'<span class="ltr" dir="ltr">\u2066{text}\u2069</span>'


def code_ltr(text):
    return f'<code class="ltr" dir="ltr">\u2066{text}\u2069</code>'


def build_dynamic_opsec_bans(agg, extra_bans=None):
    meta = agg["session_meta"]
    bans = set()
    for ip_val in (meta.get("isp_public_ip"), meta.get("control_public_ip"), meta.get("src_ip"), meta.get("gw_ip")):
        if ip_val:
            bans.add(ip_val)
            parts = ip_val.split(".")
            if len(parts) == 4 and (parts[0] in ("192", "172") or not ip_val.startswith("10.10.34.")):
                bans.add(".".join(parts[:3]) + ".")
    ignore_names = {"root", "user", "admin", "kali", "ubuntu", "localhost", "debian", BRAND.lower(), APP_NAME.lower()}
    try:
        user_name = getpass.getuser()
        if user_name and len(user_name) >= 3 and user_name.lower() not in ignore_names:
            bans.add(user_name.lower())
    except Exception:
        pass
    try:
        host_name = socket.gethostname()
        if host_name and len(host_name) >= 3 and host_name.lower() not in ignore_names:
            bans.add(host_name.lower())
    except Exception:
        pass
    home_name = pathlib.Path.home().name
    if home_name and len(home_name) >= 3 and home_name.lower() not in ignore_names:
        bans.add(home_name.lower())
    for item in extra_bans or []:
        if item and str(item).strip():
            bans.add(str(item).strip().lower())
    return sorted(bans)


def scan_opsec(target_dir, html_pairs, ban_patterns):
    hits = []
    for name, txt in html_pairs:
        low = txt.lower()
        for pat in ban_patterns:
            if pat in low:
                hits.append((name, pat))
    for p in sorted(target_dir.glob("*")):
        if p.suffix in (".md", ".txt"):
            low = p.read_text(encoding="utf-8").lower()
            for pat in ban_patterns:
                if pat in low:
                    hits.append((p.name, pat))
        elif p.suffix == ".png":
            with Image.open(p) as im:
                if im.info:
                    hits.append((p.name, f"PNG_METADATA:{list(im.info.keys())}"))
    if hits:
        raise RuntimeError(f"OPSEC_VIOLATION: {hits}")


def _render_html_to_png(html, work_dir, out_png, resize_square=None):
    tmp_pdf = work_dir / f"{out_png.stem}.pdf"
    tmp_raw = work_dir / f"{out_png.stem}_raw"
    weasyprint.HTML(string=html, base_url=str(work_dir)).write_pdf(str(tmp_pdf))
    subprocess.run(["pdftoppm", "-png", "-r", "150", "-singlefile", str(tmp_pdf), str(tmp_raw)], check=True)
    with Image.open(work_dir / f"{out_png.stem}_raw.png") as raw_im:
        im = raw_im.convert("RGB")
        if resize_square:
            im = im.resize(resize_square, Image.Resampling.LANCZOS)
        im.save(out_png, format="PNG", optimize=True)


def _x_plate_css():
    return f"""{font_face_css("fonts/")}
@page {{ size: 360mm 212mm; margin: 0; }}
* {{ box-sizing: border-box; }}
html, body {{
  margin: 0; padding: 0; width: 360mm; height: 212mm; overflow: hidden;
  font-family: "Vazirmatn FD", "Vazirmatn", sans-serif;
  direction: rtl; text-align: right; background: #f8fafc; color: #0f172a;
}}
.canvas {{
  width: 360mm; height: 212mm; padding: 7mm 9mm 6mm 9mm;
  display: flex; flex-direction: column; justify-content: space-between; background: #f8fafc;
}}
.ltr {{ direction: ltr; unicode-bidi: isolate; font-family: "Vazirmatn", "DejaVu Sans", sans-serif; }}
code.ltr {{
  direction: ltr; unicode-bidi: isolate; font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
  font-size: 8.8pt; background: #e2e8f0; color: #0f172a; border-radius: 3pt; padding: 0.5pt 4pt; white-space: nowrap;
}}
.header {{
  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 68%, #991b1b 100%);
  color: #ffffff; border-radius: 7pt; padding: 8pt 14pt;
  display: flex; justify-content: space-between; align-items: center; border-bottom: 2.5pt solid #dc2626;
}}
.header.blue {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 70%, #0369a1 100%); border-bottom-color: #0284c7; }}
.header.amber {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 65%, #92400e 100%); border-bottom-color: #d97706; }}
.hdr-title {{ font-size: 14.0pt; font-weight: 800; margin: 0 0 2pt 0; line-height: 1.3; }}
.hdr-sub {{ font-size: 8.9pt; color: #e2e8f0; margin: 0; }}
.hdr-pill {{
  background: rgba(255, 255, 255, 0.14); border: 0.8pt solid rgba(255, 255, 255, 0.35);
  border-radius: 5pt; padding: 4pt 9pt; font-size: 8.4pt; font-weight: 700; white-space: nowrap; color: #f8fafc;
}}
.kpi-row {{ display: flex; gap: 8pt; }}
.kpi {{
  flex: 1; background: #ffffff; border: 0.8pt solid #cbd5e1; border-top: 3pt solid #1e3a5f;
  border-radius: 5pt; padding: 5pt 8pt; text-align: center;
}}
.kpi.red {{ border-top-color: #b91c1c; }}
.kpi.amber {{ border-top-color: #b45309; }}
.kpi.green {{ border-top-color: #15803d; }}
.kpi-val {{ font-size: 12.2pt; font-weight: 800; color: #0f172a; line-height: 1.25; }}
.kpi-lbl {{ font-size: 7.8pt; color: #475569; margin-top: 1.5pt; }}
.grid-2 {{ display: flex; gap: 9pt; }}
.card {{ background: #ffffff; border: 0.8pt solid #cbd5e1; border-radius: 6pt; padding: 6.5pt 9pt; }}
.card-title {{
  font-size: 9.8pt; font-weight: 800; color: #0f172a; margin: 0 0 4pt 0;
  border-right: 3pt solid #1e3a5f; padding-right: 6pt;
}}
.card-title.red {{ border-right-color: #b91c1c; }}
.card-title.amber {{ border-right-color: #b45309; }}
.chart-wrap {{ display: block; text-align: center; margin: 2pt 0; }}
.chart-wrap img {{ width: auto; height: auto; max-width: 100%; max-height: 82mm; margin: 0 auto; display: block; }}
ul.bullets {{ margin: 2pt 0 0 0; padding-right: 15pt; font-size: 8.6pt; line-height: 1.52; }}
ul.bullets li {{ margin-bottom: 2.5pt; }}
.footer {{
  display: flex; justify-content: space-between; align-items: center; font-size: 8.0pt; color: #475569;
  border-top: 0.8pt solid #cbd5e1; padding-top: 3.5pt;
}}
"""


def _ig_base_css():
    return f"""{font_face_css("fonts/")}
@page {{ size: 216mm 216mm; margin: 0; }}
* {{ box-sizing: border-box; }}
html, body {{
  margin: 0; padding: 0; width: 216mm; height: 216mm; overflow: hidden;
  font-family: "Vazirmatn FD", "Vazirmatn", sans-serif;
  direction: rtl; text-align: right; background: #f8fafc; color: #0f172a;
}}
.canvas {{
  width: 216mm; height: 216mm; padding: 7.5mm 9.5mm 7mm 9.5mm;
  display: flex; flex-direction: column; justify-content: space-between;
}}
.canvas.cover {{
  background: linear-gradient(155deg, #090e1a 0%, #172554 54%, #7f1d1d 100%);
  color: #ffffff; padding: 9.5mm 11mm 8.5mm 11mm;
}}
.ltr {{ direction: ltr; unicode-bidi: isolate; font-family: "Vazirmatn", "DejaVu Sans", sans-serif; }}
code.ltr {{
  direction: ltr; unicode-bidi: isolate; font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
  font-size: 9.0pt; background: #e2e8f0; color: #0f172a; border-radius: 3pt; padding: 0.5pt 4pt; white-space: nowrap;
}}
.cover code.ltr {{ background: rgba(255,255,255,0.16); color: #ffffff; }}
.topbar {{
  display: flex; justify-content: space-between; align-items: center;
  border-bottom: 1.2pt solid #cbd5e1; padding-bottom: 4.5pt;
}}
.slide-pill {{
  background: #0f172a; color: #ffffff; font-size: 9.2pt; font-weight: 800;
  border-radius: 999pt; padding: 2.5pt 10pt;
}}
.slide-pill.red {{ background: #b91c1c; }}
.brand-tag {{ font-size: 8.6pt; color: #475569; font-weight: 700; }}
.hero-box {{
  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 68%, #991b1b 100%);
  color: #ffffff; border-radius: 7pt; padding: 7.5pt 11pt; border-right: 4pt solid #ef4444;
}}
.hero-box.blue {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 70%, #0369a1 100%); border-right-color: #38bdf8; }}
.hero-box.amber {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 65%, #92400e 100%); border-right-color: #f59e0b; }}
.h-title {{ font-size: 13.8pt; font-weight: 900; line-height: 1.35; margin: 0 0 2.5pt 0; }}
.h-sub {{ font-size: 9.2pt; color: #e2e8f0; line-height: 1.42; margin: 0; }}
.chart-card {{
  background: #ffffff; border: 0.9pt solid #cbd5e1; border-radius: 7pt; padding: 5pt 7pt; text-align: center;
}}
.chart-card img {{ width: auto; height: auto; max-width: 100%; max-height: 76mm; display: block; margin: 0 auto; }}
.point-card {{
  background: #ffffff; border: 0.9pt solid #cbd5e1; border-right: 4pt solid #b91c1c;
  border-radius: 7pt; padding: 7pt 10pt;
}}
.point-card.blue {{ border-right-color: #0284c7; }}
.point-card.amber {{ border-right-color: #d97706; }}
.point-card h3 {{ font-size: 10.4pt; font-weight: 800; margin: 0 0 3.5pt 0; color: #0f172a; }}
.point-card ul {{ margin: 0; padding-right: 14pt; font-size: 9.2pt; line-height: 1.48; }}
.point-card li {{ margin-bottom: 3pt; }}
.stat-row {{ display: flex; gap: 7pt; }}
.stat-mini {{
  flex: 1; background: #ffffff; border: 0.9pt solid #cbd5e1; border-top: 3pt solid #b91c1c;
  border-radius: 6pt; padding: 5pt 6pt; text-align: center;
}}
.stat-mini.blue {{ border-top-color: #0284c7; }}
.stat-mini.amber {{ border-top-color: #d97706; }}
.stat-val {{ font-size: 11.8pt; font-weight: 900; color: #0f172a; line-height: 1.22; }}
.stat-lbl {{ font-size: 8.0pt; color: #475569; margin-top: 1.5pt; }}
.swipe-foot {{
  display: flex; justify-content: space-between; align-items: center;
  background: #0f172a; color: #f8fafc; border-radius: 6pt; padding: 5pt 10pt; font-size: 8.8pt; font-weight: 700;
}}
.cov-kicker {{
  display: inline-block; background: rgba(239, 68, 68, 0.25); border: 1pt solid #f87171;
  color: #fecaca; border-radius: 999pt; padding: 3pt 11pt; font-size: 9.4pt; font-weight: 800;
}}
.cov-h1 {{ font-size: 22.0pt; font-weight: 900; line-height: 1.32; margin: 4pt 0 5pt 0; color: #ffffff; }}
.cov-h1 span.accent {{ color: #fca5a5; text-decoration: underline; text-decoration-color: #ef4444; }}
.cov-lead {{ font-size: 11.0pt; line-height: 1.52; color: #e2e8f0; margin: 0; }}
.cov-grid {{ display: flex; flex-direction: column; gap: 6.5pt; }}
.cov-stat {{
  background: rgba(255, 255, 255, 0.08); border: 1pt solid rgba(255, 255, 255, 0.22);
  border-right: 4.5pt solid #ef4444; border-radius: 7pt; padding: 7.5pt 11pt;
  display: flex; justify-content: space-between; align-items: center;
}}
.cov-stat.amber {{ border-right-color: #f59e0b; }}
.cov-stat.blue {{ border-right-color: #38bdf8; }}
.cov-num {{ font-size: 17.5pt; font-weight: 900; color: #ffffff; white-space: nowrap; }}
.cov-desc {{ font-size: 9.9pt; color: #f1f5f9; max-width: 71%; line-height: 1.42; }}
.cov-cta {{
  background: #dc2626; color: #ffffff; border-radius: 7pt; padding: 8pt 12pt;
  display: flex; justify-content: space-between; align-items: center; font-size: 10.6pt; font-weight: 900;
}}
"""


def _build_social_charts(tmp_dir, agg, d4, d5, rsts):
    setup_mpl_style(8.8)

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11.2, 4.1), gridspec_kw={"width_ratios": [1.0, 1.1]})
    plot_pcap_rst_hist_ax(a1, agg, rsts, compact=True)
    plot_synthetic_sni_ax(a2, agg, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "x_chart_1.png", dpi=220)
    plt.close(fig)

    fig, (b1, b2) = plt.subplots(1, 2, figsize=(11.2, 4.1), gridspec_kw={"width_ratios": [1.15, 1.0]})
    plot_cloud_matrix_ax(b1, agg, compact=True)
    plot_protocols_ax(b2, agg, d4, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "x_chart_2.png", dpi=220)
    plt.close(fig)

    fig, (c1, c2) = plt.subplots(1, 2, figsize=(11.2, 4.1), gridspec_kw={"width_ratios": [1.0, 1.15]})
    plot_speed_ax(c1, agg, d5, compact=True)
    plot_history_or_impact_ax(c2, agg, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "x_chart_3.png", dpi=220)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.8, 3.65))
    plot_synthetic_sni_ax(ax, agg, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "ig_ch_2.png", dpi=220)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.8, 3.55))
    plot_pcap_rst_hist_ax(ax, agg, rsts, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "ig_ch_3.png", dpi=220)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.8, 3.8))
    plot_cloud_matrix_ax(ax, agg, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "ig_ch_4.png", dpi=220)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.8, 3.65))
    plot_protocols_ax(ax, agg, d4, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "ig_ch_5.png", dpi=220)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.8, 3.65))
    plot_speed_ax(ax, agg, d5, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "ig_ch_6.png", dpi=220)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.8, 3.55))
    plot_history_or_impact_ax(ax, agg, compact=True)
    plt.tight_layout()
    plt.savefig(tmp_dir / "ig_ch_7.png", dpi=220)
    plt.close(fig)


def _trim_tweet(txt, limit=278):
    if len(txt) <= limit:
        return txt
    return txt[: limit - 1].rstrip() + "…"


def build_social_packages(audit_dir, agg, d2, d4, d5, rsts, extra_opsec_bans=None):
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
    pval_str = fmt_pval(rst.get("mannwhitney_u_less_pvalue"))
    dom_ttl = rst.get("dominant_rst_ttl")
    dom_pct = rst.get("dominant_ttl_share_pct", 0.0)
    dom_n = rst.get("n_dominant_ttl", 0)
    split_ex = ", ".join(agg["split_2b_bypass_hosts"][:4]) or "مسیرهای DPI"
    geo_ex = "، ".join(dpi_s["geo_isp_only_403_hosts"][:4]) or "سایت‌های تحریم خارجی"
    stalled_ex = "، ".join(ss["stalled_labels"][:3]) or "موردی ثبت نشد"
    loops = [m["label"] for m in cs.get("mtr_loop_summary", []) if m["has_loop"]]
    loop_ex = " و ".join(loops[:3]) if loops else "مسیرهای بین‌الملل"
    hist = agg.get("history_comparison") or []
    hist_line = (
        f"تکرار آزمایش در {len(hist)} نشست متوالی: RST ({' -> '.join(str(h['rst_events']) for h in hist)}) و اختلال ابرها ({' -> '.join(str(h['cloud_fail_pct']) + '%' for h in hist)})!"
        if len(hist) >= 2
        else f"ممیزی تک‌نشست روی اتصال {meta['connection_type']} با خطای محلی ۰٪!"
    )
    brand_mark = f"{APP_NAME} • {BRAND}"
    tags_line = " ".join(op["all_hashtags_fa"][:6])
    ig_tags_line = " ".join(op["all_hashtags_fa"])

    x_dir = audit_dir / "x_post_package"
    ig_dir = audit_dir / "instagram_carousel_package"
    for d in (x_dir, ig_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    ban_patterns = build_dynamic_opsec_bans(agg, extra_bans=extra_opsec_bans)

    with tempfile.TemporaryDirectory(prefix="shitnet_social_") as tmp_s:
        tmp_dir = pathlib.Path(tmp_s)
        shutil.copytree(FONTS_DIR, tmp_dir / "fonts")
        _build_social_charts(tmp_dir, agg, d4, d5, rsts)

        xp1 = f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_x_plate_css()}</style></head><body>
<div class="canvas">
  <div class="header">
    <div>
      <div class="hdr-title">وقتی نام غیرموجود روی سرور آلمانی هم قطع می‌شود: جرم‌شناسی DPI در {op['name_fa']} ({ltr(meta['asn'])})</div>
      <div class="hdr-sub">اتصال {ltr(meta['connection_type'])} — جرم‌شناسی سطح بسته {ltr('PCAP')} + تله دو سروره در آلمان ({ltr('Hetzner + Vultr')})</div>
    </div>
    <div class="hdr-pill">{ltr(meta['asn'] + ' | ' + brand_mark)}</div>
  </div>
  <div class="kpi-row">
    <div class="kpi red"><div class="kpi-val">{ltr(str(rst.get('n_events', 0)))} تزریق RST ({ltr(str(dom_pct) + '% TTL=' + str(dom_ttl))})</div><div class="kpi-lbl">احتمال تصادفی: {code_ltr('p = ' + pval_str)} (میانه {ltr(fmt_num(rst.get('median_rst_delay_ms'), ' ms'))} مقابل {ltr(fmt_num(rst.get('median_server_rtt_ms'), ' ms'))})</div></div>
    <div class="kpi amber"><div class="kpi-val">{ltr(str(syn['isp_hetzner_rst']) + ' / ' + str(syn['total']))} سرور کنترل</div><div class="kpi-lbl">قطع نام‌های جعلی {code_ltr('probe-test-404.*')} در مسیر {op['name_fa']}</div></div>
    <div class="kpi red"><div class="kpi-val">{ltr(str(syn['isp_http_blockpage']) + ' / ' + str(syn['total']))} صفحه HTTP</div><div class="kpi-lbl">تزریق صفحه فیلتر داخلی روی پورت ۸۰ سرور خارجی</div></div>
    <div class="kpi green"><div class="kpi-val">عبور با شکست {ltr('2B')}</div><div class="kpi-lbl">{ltr(str(len(agg['split_2b_bypass_hosts'])))} هدف از {ltr('split_2b')} عبور کردند ({code_ltr(split_ex)})</div></div>
  </div>
  <div class="card">
    <div class="card-title red">اثبات هم‌زمان از بسته‌های PCAP و دو سرور آزمایشی مستقل (ابطال کامل بهانه تحریم خارجی)</div>
    <div class="chart-wrap"><img src="x_chart_1.png" alt="PCAP and Synthetic SNI"></div>
  </div>
  <div class="grid-2">
    <div class="card" style="flex: 1;"><div class="card-title red">چرا بهانه «تحریم خارجی» رد می‌شود؟</div>
      <ul class="bullets">
        <li>به دو سرور آزمایشی در آلمان ({ltr('Hetzner')} و {ltr('Vultr')})، {ltr(str(syn['total']))} اسم جعلی غیرموجود فرستاده شد؛ وسط راه {ltr(str(syn['isp_hetzner_rst']))} مورد روی Hetzner و {ltr(str(syn['isp_vultr_rst']))} مورد روی Vultr قطع شدند!</li>
        <li>سایت‌های دارای تحریم واقعی ({code_ltr(geo_ex)}) ابتدا هندشیک {ltr('TLS')} را کامل می‌کنند و خود سرور ۴۰۳ می‌دهد.</li>
      </ul>
    </div>
    <div class="card" style="flex: 1;"><div class="card-title">شواهد DNS و عبور با شکست ۲ بایتی</div>
      <ul class="bullets">
        <li>با خرد کردن درخواست در بایت دوم ({code_ltr('split_2b')})، پارسر DPI جا مانده و پاسخ واقعی سرور برای {code_ltr(split_ex)} برمی‌گردد.</li>
        <li>تعداد {ltr(str(pdns.get('forged_count', 0)))} پاسخ DNS جعلی روی Resolverهای خارجی و {ltr(str(ds['port_5353_hijacked']))} ربایش روی پورت ۵۳۵۳ ثبت شد.</li>
      </ul>
    </div>
  </div>
  <div class="footer">
    <span>گزارش مستند شبکه {op['name_fa']} ({ltr(meta['asn'])}) | تولید با {ltr(brand_mark)}</span>
    <span>صفحه ۱ از ۳ | شناسه‌های شخصی و آی‌پی کاربر برای OPSEC حذف شده‌اند</span>
  </div>
</div></body></html>"""

        xp2 = f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_x_plate_css()}</style></head><body>
<div class="canvas">
  <div class="header blue">
    <div>
      <div class="hdr-title">آسیب به زیرساخت توسعه و وب: اختلال {ltr(str(cs['disrupted_pct']) + '%')} ابرهای مجاز و قطع {ltr('DoT/DoQ 853')}</div>
      <div class="hdr-sub">{ltr(str(cs['total_endpoints']))} اندپوینت ابری + ممیزی پروتکل‌های استاندارد اینترنت ({ltr('DoT / DoH / DoQ / PortQuiz / NTP')})</div>
    </div>
    <div class="hdr-pill">{ltr(str(cs['total_endpoints']) + ' Cloud Endpoints | ' + brand_mark)}</div>
  </div>
  <div class="kpi-row">
    <div class="kpi red"><div class="kpi-val">{ltr(str(cs['isp_disrupted']) + ' / ' + str(cs['total_endpoints']) + ' (' + str(cs['disrupted_pct']) + '%)')}</div><div class="kpi-lbl">اندپوینت ابری/توسعه مختل روی {op['name_fa']}</div></div>
    <div class="kpi red"><div class="kpi-val">{ltr(str(ps['dot_intl_isp_ok']) + '/' + str(ps['dot_intl_total']) + ' DoT')} و {ltr(str(ps['doq_853_isp_ok']) + '/' + str(ps['doq_853_total']) + ' DoQ')}</div><div class="kpi-lbl">وضعیت پورت {ltr('853')} در حالی که {code_ltr('portquiz: ' + str(ps['tcp_ports_isp_ok']) + '/' + str(ps['tcp_ports_total']))} باز است</div></div>
    <div class="kpi amber"><div class="kpi-val">{ltr(str(ps['doh_domain_isp_ok']) + ' / ' + str(ps['doh_domain_total']) + ' DoH')}</div><div class="kpi-lbl">{ltr(str(ps['doh_domain_isp_rst']))} مورد قطع با Reset روی سرویس‌های امن DNS</div></div>
    <div class="kpi red"><div class="kpi-val">حلقه‌های {ltr('MTR')}</div><div class="kpi-lbl">ردیابی اختلال یا حلقه روی {code_ltr(loop_ex)}</div></div>
  </div>
  <div class="card">
    <div class="card-title">وضعیت زیرساخت‌های ابری مجاز (چپ) و مسدودسازی پروتکل‌های رمزنگاری DNS (راست)</div>
    <div class="chart-wrap"><img src="x_chart_2.png" alt="Cloud Matrix and Protocols"></div>
  </div>
  <div class="grid-2">
    <div class="card" style="flex: 1;"><div class="card-title red">سرویس‌های مجاز شغلی و برنامه‌نویسی</div>
      <ul class="bullets">
        <li>بیش از <strong>{ltr(str(cs['disrupted_pct']) + '%')}</strong> سرویس‌های ابری تست‌شده (مخازن پکیج، PaaS و کلودها) روی {op['name_fa']} دچار قطع، تایم‌اوت یا تزریق RST هستند.</li>
        <li>مسیر رسیدن به {code_ltr(loop_ex)} در بررسی MTR دچار افت یا حلقه داخلی است.</li>
      </ul>
    </div>
    <div class="card" style="flex: 1;"><div class="card-title">پروتکل‌های رمزنگاری و حریم خصوصی</div>
      <ul class="bullets">
        <li>با وجود باز بودن {ltr(str(ps['tcp_ports_isp_ok']) + '/' + str(ps['tcp_ports_total']))} پورت روی {code_ltr('portquiz.net')}، پروتکل‌های امن {ltr('DoT TCP/853')} و {ltr('DoQ UDP/853')} هدفمند مختل می‌شوند.</li>
        <li>همگام‌سازی زمان {code_ltr('time.google.com')}: {ltr('سالم' if ps['ntp_google_isp_ok'] else 'قطع / تایم‌اوت')}.</li>
      </ul>
    </div>
  </div>
  <div class="footer">
    <span>گزارش زیرساخت ابری و استانداردهای وب ({ltr(meta['asn'])}) | {ltr(brand_mark)}</span>
    <span>صفحه ۲ از ۳ | ثبت خودکار با هش SHA-256 روی PCAPNG</span>
  </div>
</div></body></html>"""

        xp3 = f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_x_plate_css()}</style></head><body>
<div class="canvas">
  <div class="header amber">
    <div>
      <div class="hdr-title">سالم‌بودن خط محلی کاربر ({ltr(fmt_num(ss['local_gw_jitter_ms'], ' ms'))}) در برابر افت گزینشی و جمع‌بندی تخلفات</div>
      <div class="hdr-sub">حداکثر سرعت پایه {ltr(str(ss['max_isp_mbps']) + ' Mbps')} ({ltr(ss['max_isp_label'])}) | {ltr(hist_line)}</div>
    </div>
    <div class="hdr-pill">{ltr(brand_mark)}</div>
  </div>
  <div class="kpi-row">
    <div class="kpi green"><div class="kpi-val">{ltr(str(ss['max_isp_mbps']) + ' Mbps / ' + fmt_num(ss['local_gw_jitter_ms'], ' ms'))}</div><div class="kpi-lbl">سرعت پایه روی {code_ltr(ss['max_isp_label'])} و جیتر نزدیک به صفر محلی</div></div>
    <div class="kpi red"><div class="kpi-val">{ltr(str(len(ss['stalled_labels'])))} مقصد افت/قطع</div><div class="kpi-lbl">مقاصد کند یا تایم‌اوت‌شده: {code_ltr(stalled_ex)}</div></div>
    <div class="kpi red"><div class="kpi-val">{ltr('Fastly 5,552B' if fastly_s['stalled'] else 'Fastly OK')}</div><div class="kpi-lbl">{'قفل مسیر .18.132 سر ' + str(fastly_s['stall_bytes']) + ' B' if fastly_s['stalled'] else 'دانلود کامل مخزن دبیان'}</div></div>
    <div class="kpi amber"><div class="kpi-val">{ltr(str(rst.get('n_events', 0)))} رویداد RST</div><div class="kpi-lbl">سهم {ltr('TTL=' + str(dom_ttl))}: {ltr(str(dom_pct) + '%')} در بسته‌های PCAP</div></div>
  </div>
  <div class="card">
    <div class="card-title amber">بنچمارک دانلود (چپ) و جمع‌بندی شاخص‌های اختلال / مقایسه نشست‌ها (راست)</div>
    <div class="chart-wrap"><img src="x_chart_3.png" alt="Speed and Summary"></div>
  </div>
  <div class="grid-2">
    <div class="card" style="flex: 1;"><div class="card-title red">رد کامل بهانه «آنتن یا مودم خراب است»</div>
      <ul class="bullets">
        <li>در اتصال {ltr(meta['connection_type'])} با {code_ltr('PMTU=' + fmt_num(ps['pmtu_isp_bytes'], ' B'))} و جیتر محلی {code_ltr(fmt_num(ss['local_gw_jitter_ms'], ' ms'))}، پهنای باند پایه به {code_ltr(str(ss['max_isp_mbps']) + ' Mbps')} می‌رسد.</li>
        <li>بنابراین افت شدید فقط روی مسیرها و سرویس‌های خاص نتیجه اختلال شبکه یا اعمال محدودیت گزینشی است.</li>
      </ul>
    </div>
    <div class="card" style="flex: 1;"><div class="card-title">آماده ثبت شکایت در ۱۹۵ و تعزیرات</div>
      <ul class="bullets">
        <li>تمامی فایل‌های خام {code_ltr('PCAPNG')}، گزارش حقوقی PDF و متن‌های شکایت با امضای {ltr('SHA-256')} تولید شده‌اند.</li>
        <li>تست‌شده با ابزار متن‌باز {code_ltr(APP_NAME)} برند {code_ltr(BRAND)}.</li>
      </ul>
    </div>
  </div>
  <div class="footer">
    <span>فایل ۳ از ۳ | {op['name_fa']} ({ltr(meta['asn'])}) | {ltr(brand_mark)}</span>
    <span>نشر عمومی OPSEC-Safe بدون IP اشتراک یا نام دستگاه</span>
  </div>
</div></body></html>"""

        _render_html_to_png(xp1, tmp_dir, x_dir / "01_x_plate_dns_synthetic_and_rst_proof.png")
        _render_html_to_png(xp2, tmp_dir, x_dir / "02_x_plate_cloud_loops_and_encrypted_dns.png")
        _render_html_to_png(xp3, tmp_dir, x_dir / "03_x_plate_speed_and_summary.png")

        long_post = f"""پولی که بابت «اینترنت بین‌الملل» می‌پردازیم دقیقاً صرف چه می‌شود؟ اینترنت {op['name_fa']} ({meta['asn']}) را روی اتصال {meta['connection_type']} زیر اسکن بسته‌های خام شبکه (PCAP) بردیم تا جواب تک‌تک بهانه‌های پشتیبانی را با عدد و مدرک بدهیم:

۱) دروغِ «تحریم خارجی» رسماً ترکید:
{syn['total']} آدرس الکی و غیرموجود (با الگوی probe-test-404.*) را مستقیم به ۲ سرور کنترل روی Hetzner و Vultr در آلمان فرستادیم. حتی بدون وجود سایت خارجی، وسط راه {syn['isp_hetzner_rst']}/{syn['total']} مورد روی Hetzner و {syn['isp_vultr_rst']}/{syn['total']} مورد روی Vultr با بسته جعلی (TCP RST) قطع شدند! سایت تحریمی واقعی (مثل {geo_ex}) اول TLS باز می‌کنه و بعد خودش ۴۰۳ میده، نه فیلترچی وسط راه!

۲) مچ‌گیری ریاضی از دستگاه فیلترینگ (احتمال تصادف: p = {pval_str}):
از {rst.get('n_events', 0)} اتصالِ بریده‌شده در PCAP، سهم امضای ثابت TTL={dom_ttl} برابر {dom_pct}% ({dom_n} مورد) است و با میانه {fmt_num(rst.get('median_rst_delay_ms'), ' ms')} — در برابر {fmt_num(rst.get('median_server_rtt_ms'), ' ms')} سرور واقعی — وسط راه اتصال را می‌کُشند! وقتی درخواست را در بایت دوم خرد کردیم (split_2b)، برای {split_ex} فیلتر جا ماند و سرور واقعی جواب داد!

۳) نابودی زیرساخت کار و برنامه‌نویسی:
{cs['disrupted_pct']}% سرورهای ابری و ابزارهای کار مجاز ({cs['isp_disrupted']}/{cs['total_endpoints']}) مختل‌اند و در MTR مسیرهای {loop_ex} دچار افت یا حلقه داخلی می‌شوند. این هیچ ربطی به شبکه‌های اجتماعی ندارد!

۴) دستکاری DNS و قطع پورت ۸۵۳:
{pdns.get('forged_count', 0)} پاسخ DNS جعلی ثبت شد (شامل {ds['port_5353_hijacked']} ربایش روی پورت ۵۳۵۳) و DoT TCP/853 ({ps['dot_intl_isp_ok']}/{ps['dot_intl_total']}) و DoQ UDP/853 ({ps['doq_853_isp_ok']}/{ps['doq_853_total']}) بسته شده — در حالی که {ps['tcp_ports_isp_ok']}/{ps['tcp_ports_total']} پورت کنترلی portquiz باز است!

۵) بهانه «آنتن و سرعت» هم رد شد:
جیتر محلی {fmt_num(ss['local_gw_jitter_ms'], ' ms')} و سرعت پایه تا {ss['max_isp_mbps']} Mbps روی {ss['max_isp_label']} است؛ با این حال مسیرهای {stalled_ex} دچار افت/قطع‌اند.
{hist_line}

گزارش کامل PCAP + شکایت آماده با ابزار {APP_NAME} ({BRAND}) ساخته شد. #OPSEC
{tags_line}"""

        tweets = [
            _trim_tweet(f"اسم «اینترنت بین‌الملل» می‌فروشند، ولی بررسی PCAP روی {op['name_fa']} ({meta['asn']}) نشان می‌دهد {cs['disrupted_pct']}% زیرساخت کار و کلودها مختل است! تمام آمارها بدون سانسور (۱/۶) {tags_line.split()[0]}"),
            _trim_tweet(f"۱) بهانه «تحریم خارجی» ترکید: {syn['total']} نام جعلی و غیرموجود (probe-test-404.*) به ۲ سرور آلمان فرستادیم؛ وسط راه {syn['isp_hetzner_rst']}/{syn['total']} روی Hetzner و {syn['isp_vultr_rst']}/{syn['total']} روی Vultr با TCP RST کشته شدند! (۲/۶)"),
            _trim_tweet(f"۲) خلاف فیزیک شبکه! توی {rst.get('n_events', 0)} قطع‌شده در PCAP، {dom_pct}% امضای ثابت TTL={dom_ttl} دارن و توی {fmt_num(rst.get('median_rst_delay_ms'), 'ms')}—مقابل {fmt_num(rst.get('median_server_rtt_ms'), 'ms')} سرور واقعی (p={pval_str})—اتصالو می‌بُرن! با split_2b رد میشه! (۳/۶)"),
            _trim_tweet(f"۳) هیچ ربطی به شبکه‌های اجتماعی نداره: {cs['isp_disrupted']}/{cs['total_endpoints']} ({cs['disrupted_pct']}%) سرویس ابری و توسعه دنیا مختل‌اند و MTR در مسیر {loop_ex} گیر یا حلقه دارد! (۴/۶)"),
            _trim_tweet(f"۴) خط کاربر سالمه: جیتر محلی {fmt_num(ss['local_gw_jitter_ms'], 'ms')} و سرعت روی {ss['max_isp_label']} برابر {ss['max_isp_mbps']}Mbps هست، اما مسیرهای {stalled_ex} افت شدید یا توقف دارند! (۵/۶)"),
            _trim_tweet(f"۵) تغییر DNS هم دروغه: {pdns.get('forged_count', 0)} پاسخ جعلی در PCAP، قطع DoT ({ps['dot_intl_isp_ok']}/{ps['dot_intl_total']}) و DoQ ({ps['doq_853_isp_ok']}/{ps['doq_853_total']}) با وجود باز بودن portquiz! گزارش آماده با {APP_NAME} ({BRAND}) (۶/۶)"),
        ]
        thread_txt = ""
        for idx, tw in enumerate(tweets, 1):
            thread_txt += f"--- توییت {idx} ({len(tw)} کاراکتر) ---\n{tw}\n\n"

        (x_dir / "00_راهنمای_انتشار_و_امنیت_X.md").write_text(
            f"# راهنمای انتشار امن در X ({APP_NAME} — {BRAND})\n\n"
            f"- ۳ پلیت با رزولوشن HD و اسکن خودکار **OPSEC** تولید شدند.\n"
            f"- فایل `01_پست_بلند_ایکس_آماده.txt` برای X Premium و `02_رشته_توییت_ایکس_کوتاه_رایگان.txt` برای اکانت عادی است.\n",
            encoding="utf-8",
        )
        (x_dir / "01_پست_بلند_ایکس_آماده.txt").write_text(long_post + "\n", encoding="utf-8")
        (x_dir / "02_رشته_توییت_ایکس_کوتاه_رایگان.txt").write_text(thread_txt, encoding="utf-8")

        ig_slides = [
            (
                "01_ig_slide_hook_cover.png",
                f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_ig_base_css()}</style></head><body>
<div class="canvas cover">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <span class="cov-kicker">گزارش مستند جرم‌شناسی شبکه | {op['name_fa']} ({ltr(meta['asn'])})</span>
    <span style="font-size:9.6pt; color:#cbd5e1; font-weight:700;">اسلاید ۱ از ۷ • {ltr(brand_mark)}</span>
  </div>
  <div>
    <h1 class="cov-h1">اسم «<span class="accent">اینترنت بین‌الملل</span>» را می‌فروشند، ولی دسترسی شما را از وسط راه می‌بُرن!</h1>
    <p class="cov-lead">نتایج اسکن بسته‌های خام شبکه ({ltr('PCAP')}) روی {op['name_fa']} ({ltr(meta['connection_type'])}) با خطای محلی {code_ltr(fmt_num(ss['local_gw_jitter_ms'], ' ms'))}:</p>
  </div>
  <div class="cov-grid">
    <div class="cov-stat">
      <div class="cov-desc"><strong>{ltr(str(syn['isp_hetzner_rst']) + ' از ' + str(syn['total']))} اسمِ الکیِ غیرموجود</strong> هم وسط راه روی سرورهای آلمان کشته شدند — بهانه «تحریم خارجی» رسماً ترکید!</div>
      <div class="cov-num">{ltr(str(syn['isp_hetzner_rst']) + ' / ' + str(syn['total']))}</div>
    </div>
    <div class="cov-stat amber">
      <div class="cov-desc"><strong>{ltr(str(rst.get('n_events', 0)))} قطع مصنوعی در PCAP</strong> ({ltr(str(dom_pct) + '%')} با امضای ثابت {code_ltr('TTL=' + str(dom_ttl))}) قبل از پاسخ سرور اروپا!</div>
      <div class="cov-num">{ltr(str(rst.get('n_events', 0)) + ' RST')}</div>
    </div>
    <div class="cov-stat blue">
      <div class="cov-desc"><strong>{ltr(str(cs['disrupted_pct']) + '%')} کلودها و ابزارهای کار دنیا</strong> ({ltr(str(cs['isp_disrupted']) + '/' + str(cs['total_endpoints']))}) مختل و سرعت پایه تا {code_ltr(str(ss['max_isp_mbps']) + ' Mbps')}!</div>
      <div class="cov-num">{ltr(str(cs['disrupted_pct']) + '%')}</div>
    </div>
  </div>
  <div class="cov-cta">
    <span>ورق بزنید تا مدرک عددی هر لایه را به زبان ساده ببینید</span>
    <span>{ltr('← 1 / 7')}</span>
  </div>
</div></body></html>""",
            ),
            (
                "02_ig_slide_fake_sni_trap.png",
                f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_ig_base_css()}</style></head><body>
<div class="canvas">
  <div class="topbar"><span class="slide-pill red">اسلاید ۲ از ۷ | دروغِ «تحریم خارجی»</span><span class="brand-tag">{ltr(brand_mark)}</span></div>
  <div class="hero-box">
    <div class="h-title">{ltr(str(syn['total']))} اسمِ وجودندار به آلمان فرستادیم؛ {ltr(str(syn['isp_hetzner_rst']))} تاشو وسط راه کشتند!</div>
    <div class="h-sub">تله کنترل دو سروره روی {ltr('Hetzner')} و {ltr('Vultr')} برای ابطال بهانه خطای سایت خارجی</div>
  </div>
  <div class="chart-card"><img src="ig_ch_2.png" alt="Synthetic SNI"></div>
  <div class="point-card">
    <h3>این آزمایش به زبان ساده چی میگه؟</h3>
    <ul>
      <li>{ltr(str(syn['total']))} اسم غیرموجود ({code_ltr('probe-test-404.*')}) به آلمان ارسال شد: {ltr(str(syn['isp_hetzner_rst']))} مورد روی Hetzner و {ltr(str(syn['isp_vultr_rst']))} روی Vultr با {code_ltr('TCP RST')} قطع شدند!</li>
      <li>سایت تحریمی واقعی ({code_ltr(geo_ex)}) اول هندشیک {ltr('TLS')} را باز می‌کنه و خود سایت کد ۴۰۳ میده، نه دستگاه وسط راه ایران!</li>
    </ul>
  </div>
  <div class="swipe-foot"><span>اسلاید بعدی: بسته‌ای که سریع‌تر از سرور اروپا برگشت!</span><span>{ltr('← 2 / 7')}</span></div>
</div></body></html>""",
            ),
            (
                "03_ig_slide_pcap_speed_of_light.png",
                f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_ig_base_css()}</style></head><body>
<div class="canvas">
  <div class="topbar"><span class="slide-pill red">اسلاید ۳ از ۷ | مچ‌گیری در سطح بسته ({ltr('PCAP')})</span><span class="brand-tag">{ltr(brand_mark)}</span></div>
  <div class="hero-box">
    <div class="h-title">سرور آلمان هنوز «سلام» نکرده، وسط راه از طرفش قطع می‌کنند!</div>
    <div class="h-sub">زمان قطع میانی: {ltr(fmt_num(rst.get('median_rst_delay_ms'), ' ms'))} مقابل {ltr(fmt_num(rst.get('median_server_rtt_ms'), ' ms'))} سرور | احتمال تصادفی: {code_ltr('p = ' + pval_str)}</div>
  </div>
  <div class="stat-row">
    <div class="stat-mini"><div class="stat-val">{ltr(fmt_num(rst.get('median_rst_delay_ms'), ' ms'))}</div><div class="stat-lbl">میانه قطع جعلی (حداقل {ltr(fmt_num(rst.get('min_rst_delay_ms'), ' ms'))})</div></div>
    <div class="stat-mini blue"><div class="stat-val">{ltr(fmt_num(rst.get('median_server_rtt_ms'), ' ms'))}</div><div class="stat-lbl">میانه رسیدن واقعی به سرور ({ltr('SYN-ACK')})</div></div>
    <div class="stat-mini amber"><div class="stat-val">{ltr(str(dom_pct) + '%')}</div><div class="stat-lbl">{ltr(str(dom_n) + '/' + str(rst.get('n_events', 0)))} با امضای {code_ltr('TTL = ' + str(dom_ttl))}</div></div>
  </div>
  <div class="chart-card"><img src="ig_ch_3.png" style="max-height:66mm;" alt="PCAP RST Timing"></div>
  <div class="point-card">
    <h3>دورزدن با شکست ۲ بایتی ({code_ltr('split_2b')}):</h3>
    <ul>
      <li>در {ltr(str(rst.get('n_early_rst', 0)))} از {ltr(str(rst.get('n_events', 0)))} اتصال، بسته قطع پیش از جواب سرور از داخل شلیک شده! با تقسیم در بایت دوم برای {code_ltr(split_ex)} اتصال مستقیم باز شد!</li>
    </ul>
  </div>
  <div class="swipe-foot"><span>اسلاید بعدی: آسیب به ابزارهای کار و کلودهای دنیا</span><span>{ltr('← 3 / 7')}</span></div>
</div></body></html>""",
            ),
            (
                "04_ig_slide_cloud_and_loops.png",
                f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_ig_base_css()}</style></head><body>
<div class="canvas">
  <div class="topbar"><span class="slide-pill">اسلاید ۴ از ۷ | نابودی ابزارهای کار و توسعه</span><span class="brand-tag">{ltr(brand_mark)}</span></div>
  <div class="hero-box blue">
    <div class="h-title">فقط شبکه اجتماعی نیست؛ {ltr(str(cs['disrupted_pct']) + '%')} زیرساخت کار دنیا مختل است!</div>
    <div class="h-sub">{ltr(str(cs['isp_disrupted']) + ' از ' + str(cs['total_endpoints']))} سرویس ابری، مخزن کد و CDN دچار قطع، RST یا حلقه مسیر است</div>
  </div>
  <div class="chart-card"><img src="ig_ch_4.png" alt="Cloud Matrix"></div>
  <div class="point-card blue">
    <h3>این خرابی دقیقا چی رو فلج کرده؟</h3>
    <ul>
      <li>سرویس‌های توسعه و کلودهای تجاری دچار {code_ltr('Blackhole')} یا قطع {ltr('TLS RST')} روی {op['name_fa']} شده‌اند.</li>
      <li>بسته‌های ارسالی به {code_ltr(loop_ex)} در ردیابی {ltr('MTR')} دچار افت یا حلقه داخلی می‌شوند!</li>
    </ul>
  </div>
  <div class="swipe-foot"><span>اسلاید بعدی: چرا تغییر DNS هم کار نمی‌کند؟</span><span>{ltr('← 4 / 7')}</span></div>
</div></body></html>""",
            ),
            (
                "05_ig_slide_dns_hijack_and_port853.png",
                f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_ig_base_css()}</style></head><body>
<div class="canvas">
  <div class="topbar"><span class="slide-pill">اسلاید ۵ از ۷ | دستکاری DNS و پورت ۸۵۳</span><span class="brand-tag">{ltr(brand_mark)}</span></div>
  <div class="hero-box blue">
    <div class="h-title">عوض کردن DNS هم بی‌فایده شد؛ {ltr(str(pdns.get('forged_count', 0)))} جعل + پورت {ltr('853')}</div>
    <div class="h-sub">ربایش درخواست‌های خارجی و وضعیت {ltr('DoT / DoH / DoQ')}</div>
  </div>
  <div class="chart-card"><img src="ig_ch_5.png" alt="Protocols"></div>
  <div class="point-card blue">
    <h3>وقتی پشتیبانی میگه «DNS رو عوض کن»:</h3>
    <ul>
      <li>در {ltr('PCAP')} تعداد <strong>{ltr(str(pdns.get('forged_count', 0)))} پاسخ جعلی DNS</strong> روی Resolverهای خارجی (از جمله {ltr(str(ds['port_5353_hijacked']))} مورد روی پورت ۵۳۵۳) ثبت شد.</li>
      <li>سرورهای امن <strong>{ltr('DoT TCP/853 (' + str(ps['dot_intl_isp_ok']) + '/' + str(ps['dot_intl_total']) + ')')} و {ltr('DoQ UDP/853 (' + str(ps['doq_853_isp_ok']) + '/' + str(ps['doq_853_total']) + ')')}</strong> با وجود باز بودن {code_ltr(str(ps['tcp_ports_isp_ok']) + '/' + str(ps['tcp_ports_total']) + ' PortQuiz')} مختل هستند!</li>
    </ul>
  </div>
  <div class="swipe-foot"><span>اسلاید بعدی: تست سرعت پایه و بهانه آنتن کاربر</span><span>{ltr('← 5 / 7')}</span></div>
</div></body></html>""",
            ),
            (
                "06_ig_slide_speed_collapse_fastly.png",
                f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_ig_base_css()}</style></head><body>
<div class="canvas">
  <div class="topbar"><span class="slide-pill">اسلاید ۶ از ۷ | بهانه «آنتن و سرعت»</span><span class="brand-tag">جیتر محلی {ltr(fmt_num(ss['local_gw_jitter_ms'], ' ms'))}</span></div>
  <div class="hero-box amber">
    <div class="h-title">سرعت پایه ما {ltr(str(ss['max_isp_mbps']) + ' Mbps')} هست، پس چرا بقیه سرویس‌ها قفل میشن؟!</div>
    <div class="h-sub">خط محلی کاملاً سالم است؛ افت گزینشی روی مقاصد خاص رخ می‌دهد</div>
  </div>
  <div class="chart-card"><img src="ig_ch_6.png" alt="Speed Benchmarks"></div>
  <div class="point-card amber">
    <h3>وقتی میگن «آنتن گوشی ضعیفه یا حجم تموم شده»:</h3>
    <ul>
      <li>جیتر گیت‌وی محلی تنها {code_ltr(fmt_num(ss['local_gw_jitter_ms'], ' ms'))} و دانلود از {code_ltr(ss['max_isp_label'])} معادل <strong>{ltr(str(ss['max_isp_mbps']) + ' Mbps')}</strong> است!</li>
      <li>اما روی همین خط مقاصدی مانند {code_ltr(stalled_ex)} دچار افت شدید یا قطع می‌شوند!</li>
    </ul>
  </div>
  <div class="swipe-foot"><span>اسلاید آخر: جمع‌بندی و مدارک شکایت</span><span>{ltr('← 6 / 7')}</span></div>
</div></body></html>""",
            ),
            (
                "07_ig_slide_before_vs_now_cta.png",
                f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>{_ig_base_css()}</style></head><body>
<div class="canvas">
  <div class="topbar"><span class="slide-pill red">اسلاید ۷ از ۷ | جمع‌بندی و پیگیری رسمی</span><span class="brand-tag">{ltr(brand_mark)}</span></div>
  <div class="hero-box">
    <div class="h-title">{'مقایسه با تست‌های قبلی: اوضاع هنوز خراب است!' if len(hist) >= 2 else 'کارنامه کامل اختلالات روی این اتصال'}</div>
    <div class="h-sub">{hist_line}</div>
  </div>
  <div class="chart-card"><img src="ig_ch_7.png" alt="Summary"></div>
  <div class="point-card">
    <h3>گزارش خودکار و آماده ثبت شکایت:</h3>
    <ul>
      <li>تمام مدارک خام {code_ltr('PCAPNG')}، گزارش حقوقی {ltr('PDF')} و متن‌های شکایت برای {ltr('195')}، تعزیرات و پشتیبانی {ltr(op['support_code'])} با امضای {ltr('SHA-256')} آماده شدند.</li>
      <li>برای تست خط خودتان ابزار متن‌باز <strong>{ltr(APP_NAME)}</strong> ({ltr(BRAND)}) روی گیتهاب در دسترس است.</li>
    </ul>
  </div>
  <div class="swipe-foot" style="background:#b91c1c;">
    <span>ذخیره کنید (Save) • بفرستید برای همکاران • خودتان هم تست بگیرید</span>
    <span>{ltr('7 / 7')}</span>
  </div>
</div></body></html>""",
            ),
        ]

        for fn, html in ig_slides:
            _render_html_to_png(html, tmp_dir, ig_dir / fn, resize_square=(1080, 1080))

        ig_caption = f"""=== ۱. تیترها و هوک‌های خط اول ===
گزینه ۱:
{syn['total']} اسمِ الکی و وجودندار رو فرستادیم به سرور آلمان؛ {op['name_fa']} {syn['isp_hetzner_rst']} تاشو وسط راه کشت! دیگه بهانه «تحریم» تموم شد 👇

گزینه ۲:
اسم «اینترنت بین‌الملل» رو می‌فروشند، ولی {cs['disrupted_pct']}% کلودها و زیرساخت کار دنیا روی {op['name_fa']} مختله! 📉

=== ۲. متن کامل کپشن اینستاگرام (تند، فنی و همه‌فهم) ===
{syn['total']} تا اسمِ الکی و وجودندار رو مستقیم فرستادیم به ۲ سرور آلمان؛ وسط راه {syn['isp_hetzner_rst']} تاشو کشتن! 🤯
برای بستن راه هر بهانه («آنتن ضعیفه»، «سایت تحریمه»، «فقط اینستاگرام فیلتره»)، اتصال {meta['connection_type']} روی {op['name_fa']} ({meta['asn']}) رو با ابزار متن‌باز {APP_NAME} ({BRAND}) زیر اسکن بسته‌های خام شبکه (PCAP) بردیم:

۱) دروغِ «تحریم» ترکید: از {syn['total']} دامنه غیرموجود (probe-test-404.*)، {syn['isp_hetzner_rst']} مورد روی Hetzner و {syn['isp_vultr_rst']} مورد روی Vultr با بسته جعلی قطع شدند؛ ولی سایت تحریمی واقعی ({geo_ex}) اول وصل میشه و بعد خود سایت ۴۰۳ میده!
۲) سریع‌تر از سرور اروپا: از {rst.get('n_events', 0)} اتصال بریده‌شده، {dom_pct}% امضای ثابت TTL={dom_ttl} دارن و توی {fmt_num(rst.get('median_rst_delay_ms'), ' ms')} (مقابل {fmt_num(rst.get('median_server_rtt_ms'), ' ms')} سرور واقعی؛ احتمال تصادفی {pval_str}) ارتباطو می‌کُشن! با شکست ۲ بایتی (split_2b) فیلتر جا می‌مونه!
۳) آسیب به ابزار کار: {cs['disrupted_pct']}% سرویس‌های ابری ({cs['isp_disrupted']}/{cs['total_endpoints']}) مختل‌اند و جیتر محلی کاربر فقط {fmt_num(ss['local_gw_jitter_ms'], ' ms')} با سرعت پایه تا {ss['max_isp_mbps']} Mbps روی {ss['max_isp_label']} هست؛ اما مقاصد {stalled_ex} قفل/کند می‌شن!
۴) DNS جعلی و پورت ۸۵۳: {pdns.get('forged_count', 0)} پاسخ جعلی در PCAP ثبت شد و DoT ({ps['dot_intl_isp_ok']}/{ps['dot_intl_total']}) و DoQ UDP/853 ({ps['doq_853_isp_ok']}/{ps['doq_853_total']}) با وجود باز بودن portquiz قطع‌اند!
{hist_line}

اسلایدها رو تا ۷ ورق بزنید که با چشم خودتون عدد و مدرک رو ببینید 👆

=== ۳. هشتگ‌ها ===
{ig_tags_line}

=== ۴. متن آماده استوری ===
{syn['total']} اسم الکی فرستادیم به سرور آلمان؛ {op['name_fa']} {syn['isp_hetzner_rst']} تاشو وسط راه کشت! 🤯
حتماً این پست ۷ اسلایدی رو ورق بزنید و تست خط خودتون رو هم بگیرید 👇
"""
        (ig_dir / "00_راهنمای_انتشار_اینستاگرام.md").write_text(
            f"# راهنمای انتشار اسلایدی در اینستاگرام ({APP_NAME} — {BRAND})\n\n"
            "- تمام ۷ اسلاید دقیقاً با ابعاد مربع **1080x1080 (1:1)** و بدون متادیتا تولید شده‌اند.\n"
            "- کپشن و هشتگ‌ها متناسب با اپراتور شما در `01_تیتر_کپشن_و_هشتگ_اینستاگرام.txt` آماده‌اند.\n",
            encoding="utf-8",
        )
        (ig_dir / "01_تیتر_کپشن_و_هشتگ_اینستاگرام.txt").write_text(ig_caption, encoding="utf-8")

        scan_opsec(x_dir, [("plate1", xp1), ("plate2", xp2), ("plate3", xp3)], ban_patterns)
        scan_opsec(ig_dir, [(fn, h) for fn, h in ig_slides], ban_patterns)

    return {"x_dir": str(x_dir), "ig_dir": str(ig_dir), "opsec_bans_checked": len(ban_patterns)}

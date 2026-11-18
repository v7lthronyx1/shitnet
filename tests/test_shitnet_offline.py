import json
import pathlib
import subprocess
import tempfile
import tokenize
import unittest
from PIL import Image
from shitnet import APP_NAME, AUTHOR, BRAND
from shitnet.analytics import compute_aggregated
from shitnet.cli import render_existing_audit
from shitnet.operators import resolve_operator


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _make_synthetic_dataset(has_control=True, isp_ip="95.64.200.55", asn="AS44244", org="Iran Cell Service"):
    op = resolve_operator(asn, org)
    domains = []
    domain_dpi = []
    for i, (cat, dom) in enumerate([
        ("cloud_dev_cdn", "pages.dev"),
        ("cloud_dev_cdn", "netlify.app"),
        ("linux_pkgs", "deb.debian.org"),
        ("ai_ml_research", "openai.com"),
        ("social_video", "x.com"),
        ("search_infra", "google.com"),
        ("domestic_ir", "aparat.com"),
    ]):
        is_sink = dom in ("x.com",)
        is_safe = dom in ("google.com",)
        verdict = "SINKHOLE_10_10_34_X" if is_sink else ("FORCED_SAFESEARCH" if is_safe else "CLEAN_OR_REAL_IP")
        domains.append({
            "category": cat,
            "domain": dom,
            "verdict_gw": verdict,
            "verdict_quad9_intercept": verdict,
            "isp_gw_a": {"ok": True, "rcode": "NOERROR", "ips": ["10.10.34.36"] if is_sink else (["216.239.38.120"] if is_safe else ["104.18.20.135"]), "rtt_ms": 25.0},
            "isp_quad9_a": {"ok": True, "rcode": "NOERROR", "ips": ["10.10.34.36"] if is_sink else ["104.18.20.135"], "rtt_ms": 24.0},
            "isp_114_a": None,
            "isp_gw_aaaa": {"ok": True, "ips": []},
            "isp_gw_https": {"ok": True, "ips": [], "other": [], "cnames": []},
            "isp_dnssec": {"ad": False, "has_rrsig": i % 2 == 0},
            "control_a": {"ok": True, "rcode": "NOERROR", "ips": ["172.66.0.227" if dom == "x.com" else "142.250.185.206"]},
            "control_https_count": 1 if i < 4 else 0,
            "control_dnssec": {"ad": False, "has_rrsig": i < 5},
        })
        if dom in ("pages.dev", "netlify.app", "x.com"):
            tls_out = "TCP_RST_INJECTED"
            isp_https = None
            ctl_https = {"ok": True, "status": 200} if has_control else None
        elif dom == "openai.com":
            tls_out = "TLS_SERVER_HELLO"
            isp_https = {"ok": True, "status": 403}
            ctl_https = {"ok": True, "status": 200} if has_control else None
        elif dom == "deb.debian.org":
            tls_out = "TCP_TIMEOUT"
            isp_https = None
            ctl_https = {"ok": True, "status": 200} if has_control else None
        else:
            tls_out = "TLS_SERVER_HELLO"
            isp_https = {"ok": True, "status": 200}
            ctl_https = {"ok": True, "status": 200} if has_control else None

        domain_dpi.append({
            "category": cat,
            "domain": dom,
            "real_ip": "104.18.20.135",
            "isp_tls": {"ok": tls_out == "TLS_SERVER_HELLO", "outcome": tls_out, "tcp_ms": 80.0, "tls_ms": 95.0, "error": None},
            "control_tls": {"ok": True, "outcome": "TLS_SERVER_HELLO", "tcp_ms": 85.0, "tls_ms": 170.0, "error": None} if has_control else None,
            "isp_https": isp_https,
            "control_https": ctl_https,
            "isp_http": {"ok": False, "status": 403, "block_sig": "ISP_HTTP_BLOCKPAGE_NSV2" if is_sink else None, "snippet": "", "error": None},
        })

    d1 = {
        "timestamp_utc": "2026-11-18T12:00:00+00:00",
        "has_control": has_control,
        "network_identity": {
            "interface": "wlan99",
            "connection_type": "Wi-Fi",
            "src_ip": "192.168.43.88",
            "gw_ip": "192.168.43.1",
            "isp_public_ip": isp_ip,
            "control_public_ip": "198.51.100.77" if has_control else "",
            "asn": op["asn"],
            "prefix": "95.64.200.0/22",
            "operator": op,
            "ipinfo": {"ip": isp_ip},
            "ripe_prefix_overview": {},
            "whoami_akamai_gw": {"ok": False},
        },
        "resolver_probes": [
            {"label": "Quad9-1-UDP", "server": "9.9.9.9", "port": 53, "proto": "udp", "results": {"x.com": {"ok": True, "ips": ["10.10.34.36"]}}},
            {"label": "OpenDNS-5353-UDP", "server": "208.67.222.222", "port": 5353, "proto": "udp", "results": {"x.com": {"ok": True, "ips": ["10.10.34.36"]}}},
        ],
        "domains_count": len(domains),
        "domains": domains,
    }

    synth = []
    for name in ("probe-test-404.pages.dev", "probe-test-404.netlify.app", "fsn1-speed.hetzner.com", "probe-test-404.linode.com"):
        blk = "pages.dev" in name or "netlify.app" in name
        synth.append({
            "synthetic_sni": name,
            "isp_hetzner": {"ok": not blk, "outcome": "TCP_RST_INJECTED" if blk else "TLS_SERVER_HELLO"},
            "control_hetzner": {"ok": True, "outcome": "TLS_SERVER_HELLO"} if has_control else None,
            "isp_vultr": {"ok": not blk, "outcome": "TCP_RST_INJECTED" if blk else "TLS_SERVER_HELLO"},
            "isp_http_host_hetzner": {"ok": not blk, "block_sig": "ISP_HTTP_BLOCKPAGE_NSV2" if blk else None},
        })

    evasion = [
        {
            "host": "x.com",
            "ip": "104.16.132.229",
            "modes": {
                m: {"ok": m in ("split_2b", "rec_split_2"), "outcome": "TLS_SERVER_HELLO" if m in ("split_2b", "rec_split_2") else "TCP_RST_INJECTED"}
                for m in ("normal", "tls12", "pad1800", "ech_grease", "split_5b", "split_midsni", "split_2b", "rec_split_2", "rec_split_5")
            },
        }
    ]
    d2 = {
        "timestamp_utc": d1["timestamp_utc"],
        "has_control": has_control,
        "domain_dpi_count": len(domain_dpi),
        "domain_dpi": domain_dpi,
        "synthetic_sni_probes": synth,
        "evasion_matrix": evasion,
    }

    d3 = {
        "timestamp_utc": d1["timestamp_utc"],
        "has_control": has_control,
        "endpoints_count": 3,
        "endpoints": [
            {"provider": "DigitalOcean", "host": "fra1.digitaloceanspaces.com", "sni": "fra1.digitaloceanspaces.com", "ip": "5.101.109.44", "status": "ISP_DPI_TLS_RST", "isp": {"tcp_ok": True, "tls_ok": False, "tcp_ms": 95, "error": "Reset"}, "control": {"tcp_ok": True, "tls_ok": True, "tcp_ms": 120} if has_control else None, "isp_ping": {"loss_pct": 0}},
            {"provider": "Microsoft", "host": "microsoft.com-150.171.109.71", "sni": "microsoft.com", "ip": "150.171.109.71", "status": "ISP_CORE_ROUTING_LOOP", "isp": {"tcp_ok": False, "tls_ok": False, "tcp_ms": None, "error": "No route"}, "control": {"tcp_ok": True, "tls_ok": True, "tcp_ms": 110} if has_control else None, "isp_ping": {"loss_pct": 100}},
            {"provider": "Cloudflare", "host": "workers.dev", "sni": "workers.dev", "ip": "172.66.47.41", "status": "OK_BOTH" if has_control else "OK_DIRECT", "isp": {"tcp_ok": True, "tls_ok": True, "tcp_ms": 60, "error": None}, "control": {"tcp_ok": True, "tls_ok": True, "tcp_ms": 80} if has_control else None, "isp_ping": {"loss_pct": 0}},
        ],
        "mtr_traces": [],
        "mtr_loop_summary": [
            {"label": "Microsoft-Edge-1", "ip": "150.171.109.71", "max_hop": 30, "reached": False, "has_loop": True, "loop_ips": ["10.21.212.11", "10.21.212.20"], "last_loss_pct": 60.0, "worst_ms": 3800.0},
            {"label": "Hetzner-FSN1", "ip": "78.46.170.2", "max_hop": 13, "reached": True, "has_loop": False, "loop_ips": [], "last_loss_pct": 0.0, "worst_ms": 92.0},
        ],
    }

    d4 = {
        "timestamp_utc": d1["timestamp_utc"],
        "has_control": has_control,
        "portquiz_ip": "35.180.86.68",
        "tcp_ports": [{"port": 443, "isp": {"ok": True, "ms": 75.0, "err": None}, "control": {"ok": True, "ms": 90.0, "err": None} if has_control else None}, {"port": 853, "isp": {"ok": True, "ms": 76.0, "err": None}, "control": {"ok": True, "ms": 92.0, "err": None} if has_control else None}],
        "dot": [{"label": "Cloudflare-1.1.1.1", "ip": "1.1.1.1", "sni": "cloudflare-dns.com", "isp": {"dns_ok": False, "err": "TimeoutError: timed out"}, "control": {"dns_ok": True} if has_control else None}],
        "doh": [{"label": "Cloudflare-Domain", "host_hdr": "cloudflare-dns.com", "isp": {"ok": False, "rc": 35, "err": "Connection reset by peer"}, "control": {"ok": True} if has_control else None}],
        "quic": [{"label": "AdGuard-DoQ-853", "host": "dns.adguard-dns.com", "ip": "94.140.14.14", "port": 853, "isp_aioquic": {"ok": False}, "control_aioquic": {"ok": True, "reply_bytes": 124} if has_control else None, "isp_http3": None, "control_http3": None}],
        "ntp": [{"host": "time.google.com", "ip": "216.239.35.0", "isp": {"ok": False}, "control": {"ok": True} if has_control else None}],
        "stun": [{"label": "Google-STUN", "host": "stun.l.google.com", "port": 19302, "ip": "142.250.21.127", "isp": {"ok": True}, "control": {"ok": True} if has_control else None}],
        "pmtu_isp": [{"payload_bytes": 1472, "wire_mtu": 1500, "ok": True}, {"payload_bytes": 1473, "wire_mtu": 1501, "ok": False}],
    }

    d5 = {
        "timestamp_utc": d1["timestamp_utc"],
        "has_control": has_control,
        "speed_benchmarks": [
            {"label": "Ubuntu-Archive-5MB", "host": "archive.ubuntu.com", "ip": "185.125.190.81", "isp": {"rc": 0, "http_code": 200, "bytes": 5242880, "mbps": 24.5, "ttfb_s": 0.2}, "control": {"rc": 0, "http_code": 200, "bytes": 5242880, "mbps": 18.0} if has_control else None},
            {"label": "Google-DL-5MB", "host": "dl.google.com", "ip": "64.233.176.91", "isp": {"rc": 28, "http_code": 200, "bytes": 400000, "mbps": 0.15, "ttfb_s": 1.1}, "control": {"rc": 0, "http_code": 200, "bytes": 5242880, "mbps": 14.0} if has_control else None},
        ],
        "fastly_thresholds": [
            {"ip": "151.101.18.132", "scheme": "http", "range": "FULL", "isp": {"rc": 28, "bytes": 5552, "mbps": 0.04}, "control": {"rc": 0, "bytes": 138612, "mbps": 8.0} if has_control else None},
            {"ip": "151.101.18.132", "scheme": "http", "range": "0-5552", "isp": {"rc": 0, "bytes": 5553, "mbps": 1.1}, "control": None},
        ],
        "jitter_bursts": [
            {"label": "Local-GW", "ip": "192.168.43.1", "isp": {"sent": 40, "recv": 40, "loss_pct": 0.0, "min_ms": 0.2, "p50_ms": 0.4, "p95_ms": 0.8, "max_ms": 1.1, "stdev_ms": 0.08}, "control": None},
            {"label": "Fastly-POP2", "ip": "151.101.130.132", "isp": {"sent": 40, "recv": 39, "loss_pct": 2.5, "min_ms": 72.0, "p50_ms": 84.0, "p95_ms": 122.0, "max_ms": 145.0, "stdev_ms": 14.5}, "control": None},
        ],
    }

    rsts = [{"server_rtt_ms": 180.0 + i, "rst_after_ch_ms": 82.0 + i, "rst_ttl": 64, "ttl_mismatch": True, "early_rst": True} for i in range(12)]
    d6 = {
        "dns_pcap_hijack_proof": {"forged_count": 18, "clean_count": 30, "forged_ttls": [64], "clean_ttls": [55], "forged_median_rtt_ms": 34.2, "clean_median_rtt_ms": 115.6, "forged_samples": [], "clean_samples": []},
        "dpi_rst_timing_ttl_proof": {
            "n_events": len(rsts),
            "dominant_rst_ttl": 64,
            "n_dominant_ttl": 12,
            "n_ttl_60": 0,
            "n_ttl_mismatch": 12,
            "n_cloned_ttl_early": 0,
            "n_early_rst": 12,
            "rst_ttl_dist": {"64": 12},
            "median_server_rtt_ms": 185.5,
            "median_rst_delay_ms": 87.5,
            "min_rst_delay_ms": 82.0,
            "max_rst_delay_ms": 93.0,
            "mannwhitney_u_less_pvalue": 1.82e-5,
            "sample_events": rsts,
        },
        "http_block_or_403_frames": [],
        "quic_udp443_packet_balance": {"udp_443_outbound_pkts": 30, "udp_443_inbound_replies": 0},
        "fastly_tcp_stats": {"n_streams": 3, "server_retransmissions": 14, "sample_streams": []},
    }
    return d1, d2, d3, d4, d5, d6, rsts


class ShitNetOfflineTests(unittest.TestCase):
    def test_operator_registry_accuracy(self):
        mci = resolve_operator("AS197207")
        self.assertEqual(mci["short_en"], "MCI")
        self.assertEqual(mci["support_code"], "9990")

        irc = resolve_operator("AS44244")
        self.assertEqual(irc["short_en"], "Irancell")
        self.assertEqual(irc["support_code"], "700")

        hw = resolve_operator("AS56402")
        self.assertEqual(hw["short_en"], "HiWEB")
        self.assertEqual(hw["support_code"], "1565")

        mb = resolve_operator("AS50810")
        self.assertEqual(mb["short_en"], "MobinNet")

        unk = resolve_operator("AS64512", "Custom Example ISP")
        self.assertEqual(unk["asn"], "AS64512")
        self.assertEqual(unk["name_fa"], "Custom Example ISP")

    def test_zero_comments_zero_ai_zero_personal_paths(self):
        py_files = sorted(REPO_ROOT.rglob("*.py"))
        self.assertGreater(len(py_files), 10)
        banned_markers = [".gemini", "antigravity", "/home/aiden", "ai-generated", "openai-codex"]
        for p in list(py_files) + [REPO_ROOT / "README.md", REPO_ROOT / "README_FA.md", REPO_ROOT / "setup.sh", REPO_ROOT / "pyproject.toml"]:
            txt = p.read_text(encoding="utf-8")
            low = txt.lower()
            if p.resolve() != pathlib.Path(__file__).resolve():
                for marker in banned_markers:
                    self.assertNotIn(marker, low, f"Forbidden trace '{marker}' found in {p}")
            if p.suffix == ".py":
                with p.open("rb") as f:
                    for tok in tokenize.tokenize(f.readline):
                        self.assertNotEqual(tok.type, tokenize.COMMENT, f"Comment found in {p}: {tok.string}")

    def test_full_synthetic_pipeline_dual_and_direct_only(self):
        for has_ctl, mode in [(True, "dual"), (False, "direct-only")]:
            with tempfile.TemporaryDirectory(prefix=f"shitnet_test_{mode}_") as td:
                audit_dir = pathlib.Path(td) / "run1"
                raw_dir = audit_dir / "raw_data"
                pcap_dir = audit_dir / "raw_pcaps"
                raw_dir.mkdir(parents=True)
                pcap_dir.mkdir(parents=True)

                d1, d2, d3, d4, d5, d6, rsts = _make_synthetic_dataset(has_control=has_ctl)
                (raw_dir / "01_deep_dns_forensics.json").write_text(json.dumps(d1), encoding="utf-8")
                (raw_dir / "02_deep_dpi_forensics.json").write_text(json.dumps(d2), encoding="utf-8")
                (raw_dir / "03_cloud_infra_forensics.json").write_text(json.dumps(d3), encoding="utf-8")
                (raw_dir / "04_protocols_forensics.json").write_text(json.dumps(d4), encoding="utf-8")
                (raw_dir / "05_throughput_jitter_forensics.json").write_text(json.dumps(d5), encoding="utf-8")
                (raw_dir / "06_pcap_deep_summary.json").write_text(json.dumps(d6), encoding="utf-8")
                (raw_dir / "06_pcap_all_rst_events.json").write_text(json.dumps(rsts), encoding="utf-8")

                render_existing_audit(audit_dir, mode=mode, build_pdf=True, build_social=True, opsec_bans=["SyntheticSecretCity"])

                charts = list((audit_dir / "charts").glob("*.png"))
                self.assertEqual(len(charts), 7)

                chk_root = subprocess.run(["sha256sum", "-c", "SHA256SUMS.txt"], cwd=str(audit_dir), capture_output=True, text=True)
                self.assertEqual(chk_root.returncode, 0, chk_root.stderr)

                pkg_dir = audit_dir / "complaint_package"
                chk_pkg = subprocess.run(["sha256sum", "-c", "PACKAGE_SHA256SUMS.txt"], cwd=str(pkg_dir), capture_output=True, text=True)
                self.assertEqual(chk_pkg.returncode, 0, chk_pkg.stderr)

                pdfs = list(pkg_dir.glob("*.pdf"))
                self.assertEqual(len(pdfs), 2)
                for pdf in pdfs:
                    self.assertGreater(pdf.stat().st_size, 10000)

                ig_slides = sorted((audit_dir / "instagram_carousel_package").glob("*.png"))
                self.assertEqual(len(ig_slides), 7)
                for slide in ig_slides:
                    with Image.open(slide) as im:
                        self.assertEqual(im.size, (1080, 1080))
                        self.assertEqual(im.info, {})

                x_plates = sorted((audit_dir / "x_post_package").glob("*.png"))
                self.assertEqual(len(x_plates), 3)
                for xp in x_plates:
                    with Image.open(xp) as im:
                        self.assertEqual(im.info, {})

                x_txt = (audit_dir / "x_post_package" / "01_پست_بلند_ایکس_آماده.txt").read_text(encoding="utf-8")
                self.assertIn(BRAND, x_txt)
                self.assertIn(APP_NAME, x_txt)
                self.assertNotIn("95.64.200.55", x_txt)
                self.assertNotIn("192.168.43.", x_txt)

                agg = compute_aggregated(d1, d2, d3, d4, d5, d6, rsts, mode=mode)
                self.assertEqual(agg["session_meta"]["asn"], "AS44244")
                self.assertEqual(AUTHOR, "Aiden Azad")

    def test_compare_multisession_progression(self):
        with tempfile.TemporaryDirectory(prefix="shitnet_cmp_") as td:
            base = pathlib.Path(td)
            run1 = base / "run1"
            run2 = base / "run2"
            for rdir, ip in [(run1, "95.64.200.55"), (run2, "95.64.201.88")]:
                (rdir / "raw_data").mkdir(parents=True)
                (rdir / "raw_pcaps").mkdir(parents=True)
                d1, d2, d3, d4, d5, d6, rsts = _make_synthetic_dataset(has_control=True, isp_ip=ip)
                (rdir / "raw_data" / "01_deep_dns_forensics.json").write_text(json.dumps(d1), encoding="utf-8")
                (rdir / "raw_data" / "02_deep_dpi_forensics.json").write_text(json.dumps(d2), encoding="utf-8")
                (rdir / "raw_data" / "03_cloud_infra_forensics.json").write_text(json.dumps(d3), encoding="utf-8")
                (rdir / "raw_data" / "04_protocols_forensics.json").write_text(json.dumps(d4), encoding="utf-8")
                (rdir / "raw_data" / "05_throughput_jitter_forensics.json").write_text(json.dumps(d5), encoding="utf-8")
                (rdir / "raw_data" / "06_pcap_deep_summary.json").write_text(json.dumps(d6), encoding="utf-8")
                (rdir / "raw_data" / "06_pcap_all_rst_events.json").write_text(json.dumps(rsts), encoding="utf-8")

            render_existing_audit(run1, mode="dual", build_pdf=False, build_social=False)
            render_existing_audit(run2, mode="dual", compare_dirs=[str(run1)], build_pdf=True, build_social=True)

            rep_fa = (run2 / "REPORT_FA.md").read_text(encoding="utf-8")
            self.assertIn("مقایسه دقیق با نشست‌های قبلی", rep_fa)
            agg2 = json.loads((run2 / "raw_data" / "07_aggregated_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(len(agg2["history_comparison"]), 2)


if __name__ == "__main__":
    unittest.main()

import argparse
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from . import APP_NAME, AUTHOR, BRAND, __version__
from .analytics import compute_aggregated, load_json_if
from .charts import generate_all_charts
from .complaint import build_complaint_package
from .netenv import (
    DualRouteGuard,
    auto_detect_topology,
    check_system_capabilities,
    detect_interface_dns,
    fetch_public_ip,
    pick_isp_dns,
)
from .probes import cloud_probe, dns_probe, dpi_probe, pcap_forensics, proto_probe, speed_probe
from .reports import build_manifest_and_hashes, write_reports
from .social import build_social_packages, build_dynamic_opsec_bans, scan_opsec


BANNER = f"""
  ____  _     _ _   _   _      _
 / ___|| |__ (_) |_| \\ | | ___| |_
 \\___ \\| '_ \\| | __|  \\| |/ _ \\ __|
  ___) | | | | | |_| |\\  |  __/ |_
 |____/|_| |_|_|\\__|_| \\_|\\___|\\__|   v{__version__}
  {BRAND} ({AUTHOR}) — Automated Network Censorship & QoS Forensics
"""


def _log(msg):
    print(msg, flush=True)


def _pick_control_dns(topo, explicit_vpn_dns=None):
    if explicit_vpn_dns:
        return explicit_vpn_dns
    vpn = topo.get("vpn_iface")
    if vpn:
        dns_list = detect_interface_dns(vpn["name"])
        if dns_list:
            return dns_list[0]
    return "1.1.1.1"


def _resolve_targets_for_quick(quick):
    if not quick:
        return None
    from .targets import DOMAINS
    cats = {}
    selected = []
    for cat, dom in DOMAINS:
        if cats.get(cat, 0) < 4:
            selected.append((cat, dom))
            cats[cat] = cats.get(cat, 0) + 1
    return selected


def run_audit_pipeline(cfg):
    out_dir = pathlib.Path(cfg["out"]).expanduser().resolve()
    raw_dir = out_dir / "raw_data"
    pcap_dir = out_dir / "raw_pcaps"
    charts_dir = out_dir / "charts"
    raw_dir.mkdir(parents=True, exist_ok=True)
    pcap_dir.mkdir(parents=True, exist_ok=True)

    mode = cfg["mode"]
    isp_iface = cfg["iface"]
    src_ip = cfg["src_ip"]
    gw_ip = cfg["gw_ip"]
    gw_dns = cfg["gw_dns"]
    ctl_dns = cfg["vpn_dns"]
    conn_type = cfg.get("conn_type")
    op_override = cfg.get("operator")
    domains = _resolve_targets_for_quick(cfg.get("quick"))

    if mode == "dual":
        with DualRouteGuard(isp_iface, src_ip, gw_ip, enabled=not cfg.get("no_auto_route")):
            _log(f"[*] Mode: dual | ISP iface: {isp_iface} ({src_ip}) | Control DNS: {ctl_dns}")
            d1_isp = dns_probe.run_isp_phase(raw_dir, pcap_dir, isp_iface, src_ip, gw_dns, domains=domains, conn_type=conn_type, operator_override=op_override, progress_cb=_log)
            d1 = dns_probe.run_control_phase(d1_isp, control_dns=ctl_dns, has_control=True, operator_override=op_override, progress_cb=_log)
            dns_probe.save_outputs(raw_dir, d1)

            pre_ips = {r["domain"]: r["control_a"]["ips"][0] for r in d1["domains"] if r["control_a"]["ips"]}
            d2_isp = dpi_probe.run_isp_phase(pcap_dir, isp_iface, src_ip, d1["domains"], domains_pre_ips=pre_ips, progress_cb=_log)
            d2 = dpi_probe.run_control_phase(d2_isp, has_control=True, progress_cb=_log)
            dpi_probe.save_outputs(raw_dir, d2)

            d3_isp = cloud_probe.run_isp_phase(pcap_dir, isp_iface, src_ip, control_dns=ctl_dns, can_resolve_control=True, dns_resolved_map={k: [v] for k, v in pre_ips.items()}, progress_cb=_log)
            d3 = cloud_probe.run_control_phase(d3_isp, has_control=True, progress_cb=_log)
            cloud_probe.save_outputs(raw_dir, d3)

            d4_isp = proto_probe.run_isp_phase(pcap_dir, isp_iface, src_ip, control_dns=ctl_dns, can_resolve=True, progress_cb=_log)
            d4 = proto_probe.run_control_phase(d4_isp, has_control=True, progress_cb=_log)
            proto_probe.save_outputs(raw_dir, d4)

            d5_isp = speed_probe.run_isp_phase(pcap_dir, isp_iface, src_ip, gw_ip, progress_cb=_log)
            d5 = speed_probe.run_control_phase(d5_isp, gw_ip, has_control=True, progress_cb=_log)
            speed_probe.save_outputs(raw_dir, d5)

    else:
        _log(f"[*] Mode: {mode} | Phase A (Direct ISP): {isp_iface} ({src_ip})")
        d1_isp = dns_probe.run_isp_phase(raw_dir, pcap_dir, isp_iface, src_ip, gw_dns, domains=domains, conn_type=conn_type, operator_override=op_override, progress_cb=_log)
        d2_isp = dpi_probe.run_isp_phase(pcap_dir, isp_iface, src_ip, [{"category": r["category"], "domain": r["domain"], "isp_gw_a": r["isp_gw_a"]} for r in d1_isp["isp_domains"]], progress_cb=_log)
        d3_isp = cloud_probe.run_isp_phase(pcap_dir, isp_iface, src_ip, can_resolve_control=False, progress_cb=_log)
        d4_isp = proto_probe.run_isp_phase(pcap_dir, isp_iface, src_ip, can_resolve=False, progress_cb=_log)
        d5_isp = speed_probe.run_isp_phase(pcap_dir, isp_iface, src_ip, gw_ip, progress_cb=_log)

        has_control = False
        if mode == "two-phase":
            isp_pub = d1_isp["network_identity"]["isp_public_ip"]
            _log("\n" + "=" * 68)
            _log("[!] Phase A (ISP Direct) finished successfully!")
            _log("[!] مرحله ۱ (تست مستقیم اپراتور) با موفقیت تمام شد!")
            _log(f"    Detected ISP Public IP: {isp_pub or 'Unknown'}")
            _log("    Now enable your clean VPN / alternate clean internet, then press ENTER.")
            _log("    اکنون VPN یا اینترنت آزاد کنترل را روشن کنید و Enter را بزنید")
            _log("    (Or type 'skip' to generate report in direct-only mode):")
            _log("=" * 68)
            while True:
                ans = input("> ").strip().lower()
                if ans in ("skip", "s", "no", "n"):
                    has_control = False
                    break
                new_ip = fetch_public_ip(source_ip=None)
                if not new_ip:
                    _log("[!] Could not reach public IP check over control route. Check VPN and press ENTER (or type 'skip').")
                    continue
                if isp_pub and new_ip == isp_pub:
                    _log(f"[!] Public IP is still {new_ip} (same as ISP). Enable VPN first or type 'skip'.")
                    continue
                _log(f"[+] Clean control path confirmed! Control Public IP: {new_ip}")
                topo_now = auto_detect_topology()
                ctl_dns = _pick_control_dns(topo_now, explicit_vpn_dns=cfg.get("vpn_dns_explicit"))
                has_control = True
                break

        d1 = dns_probe.run_control_phase(d1_isp, control_dns=ctl_dns, has_control=has_control, operator_override=op_override, progress_cb=_log)
        dns_probe.save_outputs(raw_dir, d1)
        d2 = dpi_probe.run_control_phase(d2_isp, has_control=has_control, progress_cb=_log)
        dpi_probe.save_outputs(raw_dir, d2)
        d3 = cloud_probe.run_control_phase(d3_isp, has_control=has_control, progress_cb=_log)
        cloud_probe.save_outputs(raw_dir, d3)
        d4 = proto_probe.run_control_phase(d4_isp, has_control=has_control, progress_cb=_log)
        proto_probe.save_outputs(raw_dir, d4)
        d5 = speed_probe.run_control_phase(d5_isp, gw_ip, has_control=has_control, progress_cb=_log)
        speed_probe.save_outputs(raw_dir, d5)

    d6, rsts = pcap_forensics.run_forensics(pcap_dir, raw_dir, src_ip, gw_ip, progress_cb=_log)
    return render_existing_audit(
        out_dir,
        mode=mode,
        compare_dirs=cfg.get("compare"),
        build_pdf=not cfg.get("no_pdf"),
        build_social=not cfg.get("no_social"),
        opsec_bans=cfg.get("opsec_ban"),
    )


def render_existing_audit(audit_dir, mode=None, compare_dirs=None, build_pdf=True, build_social=True, opsec_bans=None):
    audit_dir = pathlib.Path(audit_dir).expanduser().resolve()
    raw_dir = audit_dir / "raw_data"
    charts_dir = audit_dir / "charts"

    d1 = load_json_if(raw_dir / "01_deep_dns_forensics.json")
    d2 = load_json_if(raw_dir / "02_deep_dpi_forensics.json")
    d3 = load_json_if(raw_dir / "03_cloud_infra_forensics.json")
    d4 = load_json_if(raw_dir / "04_protocols_forensics.json")
    d5 = load_json_if(raw_dir / "05_throughput_jitter_forensics.json")
    d6 = load_json_if(raw_dir / "06_pcap_deep_summary.json")
    rsts = load_json_if(raw_dir / "06_pcap_all_rst_events.json") or []

    if not all([d1, d2, d3, d4, d5, d6]):
        raise FileNotFoundError(f"Missing required raw_data/*.json files inside {raw_dir}")

    effective_mode = mode or ("dual" if d1.get("has_control") else "direct-only")
    _log("[*] Computing aggregated forensic metrics...")
    agg = compute_aggregated(d1, d2, d3, d4, d5, d6, rsts, mode=effective_mode, compare_dirs=compare_dirs)

    _log("[*] Rendering 7 high-DPI diagnostic charts...")
    generate_all_charts(charts_dir, agg, d1, d2, d3, d4, d5, rsts)

    _log("[*] Writing bilingual markdown reports & SHA-256 manifest...")
    write_reports(audit_dir, raw_dir, agg, d2, d3, d4, d5)
    build_manifest_and_hashes(audit_dir)

    if build_pdf:
        _log("[*] Building legal/technical complaint PDFs & evidence mirror...")
        build_complaint_package(audit_dir, agg, d2, d4, d5)

    if build_social:
        _log("[*] Generating OPSEC-clean X plates & 1:1 Instagram carousel...")
        build_social_packages(audit_dir, agg, d2, d4, d5, rsts, extra_opsec_bans=opsec_bans)

    _log(f"[+] Complete! Output ready at: {audit_dir}")
    return audit_dir


def cmd_check_env(_args):
    print(BANNER)
    caps = check_system_capabilities()
    topo = auto_detect_topology()
    print(f"Root privileges : {caps['is_root']}")
    print(f"Dumpcap ready   : {caps['dumpcap_capture_ok']} ({caps['dumpcap_err'] or 'OK'})")
    print("System binaries :")
    for k, v in caps["tools"].items():
        print(f"  - {k:10s}: {v or 'MISSING'}")
    print("\nDetected IPv4 interfaces:")
    for inf in topo["interfaces"]:
        kind = "VPN" if inf["is_vpn"] else "ISP/LAN"
        df = " [DEFAULT]" if inf["default_route"] else ""
        print(f"  - {inf['name']:12s} ({kind:7s}) ip={inf['ip']:15s} gw={str(inf['gateway']):15s} dns={inf['dns']}{df}")
    print(f"\nSuggested ISP interface : {(topo['isp_iface'] or {}).get('name')}")
    print(f"Suggested VPN interface : {(topo['vpn_iface'] or {}).get('name')}")
    print(f"Suggested mode          : {topo['suggested_mode']}")


def cmd_verify(args):
    audit_dir = pathlib.Path(args.audit_dir).expanduser().resolve()
    sha_file = audit_dir / "SHA256SUMS.txt"
    if not sha_file.exists():
        raise SystemExit(f"Missing {sha_file}")
    p1 = subprocess.run(["sha256sum", "-c", "SHA256SUMS.txt"], cwd=str(audit_dir), capture_output=True, text=True)
    ok1 = sum(1 for l in p1.stdout.splitlines() if l.endswith(": OK"))
    if p1.returncode != 0:
        print(p1.stdout)
        print(p1.stderr)
        raise SystemExit("SHA256SUMS verification FAILED")
    print(f"[+] Root SHA256SUMS.txt OK ({ok1} files)")

    pkg_dir = audit_dir / "complaint_package"
    pkg_sha = pkg_dir / "PACKAGE_SHA256SUMS.txt"
    if pkg_sha.exists():
        p2 = subprocess.run(["sha256sum", "-c", "PACKAGE_SHA256SUMS.txt"], cwd=str(pkg_dir), capture_output=True, text=True)
        ok2 = sum(1 for l in p2.stdout.splitlines() if l.endswith(": OK"))
        if p2.returncode != 0:
            raise SystemExit("PACKAGE_SHA256SUMS verification FAILED")
        print(f"[+] Complaint PACKAGE_SHA256SUMS.txt OK ({ok2} files)")

    agg = load_json_if(audit_dir / "raw_data" / "07_aggregated_metrics.json")
    if agg:
        bans = build_dynamic_opsec_bans(agg, extra_bans=args.opsec_ban)
        for sdir_name in ("x_post_package", "instagram_carousel_package"):
            sdir = audit_dir / sdir_name
            if sdir.exists():
                scan_opsec(sdir, [], bans)
                print(f"[+] OPSEC clean: {sdir_name}")


def _build_default_cfg(args, topo):
    isp = topo.get("isp_iface") or {}
    vpn = topo.get("vpn_iface") or {}
    mode = args.mode
    if mode == "auto":
        mode = topo["suggested_mode"]
    iface = args.iface or isp.get("name")
    if not iface:
        raise SystemExit("No active network interface detected. Pass --iface explicitly.")
    selected = next((x for x in topo["interfaces"] if x["name"] == iface), isp)
    src_ip = args.src_ip or selected.get("ip")
    gw_ip = args.gw_ip or selected.get("gateway")
    gw_dns = args.gw_dns or pick_isp_dns(gw_ip, selected.get("dns"), source_ip=src_ip, iface=iface)
    vpn_dns = args.vpn_dns or ((vpn.get("dns") or [None])[0]) or "1.1.1.1"
    ts_dir = datetime.now(timezone.utc).strftime("audit_%Y%m%d_%H%M%SZ") + f"_{iface}"
    out = args.out or str(pathlib.Path.cwd() / "audits" / ts_dir)
    return {
        "mode": mode,
        "iface": iface,
        "src_ip": src_ip,
        "gw_ip": gw_ip,
        "gw_dns": gw_dns,
        "vpn_dns": vpn_dns,
        "vpn_dns_explicit": args.vpn_dns,
        "conn_type": args.conn_type,
        "operator": args.operator,
        "out": out,
        "compare": args.compare,
        "no_pdf": args.no_pdf,
        "no_social": args.no_social,
        "no_auto_route": args.no_auto_route,
        "opsec_ban": args.opsec_ban,
        "quick": args.quick,
    }


def cmd_wizard(_args):
    print(BANNER)
    caps = check_system_capabilities()
    topo = auto_detect_topology()
    if not caps["dumpcap_capture_ok"]:
        print("[!] Warning: dumpcap capture permission missing (run with sudo or setcap cap_net_raw,cap_net_admin=eip $(which dumpcap))")

    ifaces = [x for x in topo["interfaces"] if not x["is_vpn"]] or topo["interfaces"]
    if not ifaces:
        raise SystemExit("No active IPv4 interfaces found.")

    print("Active Interfaces Detected:")
    for idx, inf in enumerate(topo["interfaces"], 1):
        kind = "VPN" if inf["is_vpn"] else "ISP"
        print(f"  [{idx}] {inf['name']} ({kind}) — IP: {inf['ip']}, GW: {inf['gateway']}, DNS: {inf['dns']}")

    def_isp = topo["isp_iface"] or ifaces[0]
    raw_iface = input(f"\nISP interface name [default: {def_isp['name']}]: ").strip() or def_isp["name"]
    sel = next((x for x in topo["interfaces"] if x["name"] == raw_iface), def_isp)

    print("\nSelect Audit Comparison Mode:")
    print("  [1] dual       — Direct ISP interface + Active VPN tunnel simultaneously")
    print("  [2] two-phase  — Direct ISP first, then pause for you to turn ON VPN (Recommended for single link)")
    print("  [3] direct-only — Direct ISP forensics only (no VPN required)")
    def_m = "1" if topo["suggested_mode"] == "dual" else "2"
    m_choice = input(f"Mode [1/2/3, default: {def_m}]: ").strip() or def_m
    mode_map = {"1": "dual", "2": "two-phase", "3": "direct-only", "dual": "dual", "two-phase": "two-phase", "direct-only": "direct-only"}
    mode = mode_map.get(m_choice, topo["suggested_mode"])

    conn_type = input("Connection type label (e.g. Wi-Fi, USB Tether, Fiber) [Enter for auto]: ").strip() or None
    op_over = input("Operator override name (leave empty for auto ASN detection): ").strip() or None
    prev_dir = input("Previous audit folder(s) to compare (comma-separated, optional): ").strip()
    compare_dirs = [p.strip() for p in prev_dir.split(",") if p.strip()] if prev_dir else []
    opsec_extra = input("Extra words/city/device to block in X/IG OPSEC check (comma-separated, optional): ").strip()
    extra_bans = [w.strip() for w in opsec_extra.split(",") if w.strip()] if opsec_extra else []
    want_social = (input("Generate OPSEC-safe X plates & 1:1 Instagram carousel? [Y/n]: ").strip().lower() or "y") != "n"

    ts_dir = datetime.now(timezone.utc).strftime("audit_%Y%m%d_%H%M%SZ") + f"_{sel['name']}"
    default_out = str(pathlib.Path.cwd() / "audits" / ts_dir)
    out = input(f"Output directory [default: {default_out}]: ").strip() or default_out

    cfg = {
        "mode": mode,
        "iface": sel["name"],
        "src_ip": sel["ip"],
        "gw_ip": sel["gateway"],
        "gw_dns": pick_isp_dns(sel["gateway"], sel.get("dns"), source_ip=sel["ip"], iface=sel["name"]),
        "vpn_dns": _pick_control_dns(topo),
        "vpn_dns_explicit": None,
        "conn_type": conn_type,
        "operator": op_over,
        "out": out,
        "compare": compare_dirs,
        "no_pdf": False,
        "no_social": not want_social,
        "no_auto_route": False,
        "opsec_ban": extra_bans,
        "quick": False,
    }
    print("\n[*] Starting automated audit...\n")
    run_audit_pipeline(cfg)


def build_parser():
    p = argparse.ArgumentParser(prog="shitnet", description=f"{APP_NAME} v{__version__} ({BRAND}) — ISP Censorship & QoS Forensics")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("wizard", help="Interactive guided audit wizard")
    sub.add_parser("check-env", help="Inspect OS tools, dumpcap permissions, and interfaces")

    pr = sub.add_parser("run", help="Run automated forensic audit")
    pr.add_argument("--mode", choices=["auto", "dual", "two-phase", "direct-only"], default="auto")
    pr.add_argument("--iface", help="Direct ISP network interface (e.g. eth0, wlan0)")
    pr.add_argument("--src-ip", help="Source IPv4 bound to ISP interface")
    pr.add_argument("--gw-ip", help="ISP gateway IPv4")
    pr.add_argument("--gw-dns", help="ISP / local router DNS IPv4")
    pr.add_argument("--vpn-dns", help="Clean control DNS IPv4")
    pr.add_argument("--conn-type", help="Connection description label (Wi-Fi, USB Tether, etc.)")
    pr.add_argument("--operator", help="Override detected operator name")
    pr.add_argument("--out", help="Output audit directory")
    pr.add_argument("--compare", nargs="*", help="Prior audit directories for progression comparison")
    pr.add_argument("--opsec-ban", nargs="*", help="Extra strings to forbid in public X/IG packages")
    pr.add_argument("--no-pdf", action="store_true", help="Skip complaint PDF generation")
    pr.add_argument("--no-social", action="store_true", help="Skip X/Instagram output generation")
    pr.add_argument("--no-auto-route", action="store_true", help="Disable temporary ip rule policy routing in dual mode")
    pr.add_argument("--quick", action="store_true", help="Run shorter domain sample for rapid diagnostics")

    prd = sub.add_parser("render", help="Render charts, reports, PDFs, and social packages from existing raw_data")
    prd.add_argument("audit_dir", help="Path to audit directory containing raw_data/ and raw_pcaps/")
    prd.add_argument("--compare", nargs="*", help="Prior audit directories to compare")
    prd.add_argument("--opsec-ban", nargs="*", help="Extra OPSEC forbidden strings")
    prd.add_argument("--no-pdf", action="store_true")
    prd.add_argument("--no-social", action="store_true")

    pv = sub.add_parser("verify", help="Verify SHA-256 integrity and OPSEC cleanliness")
    pv.add_argument("audit_dir", help="Path to audit directory")
    pv.add_argument("--opsec-ban", nargs="*", help="Extra OPSEC forbidden strings")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd in (None, "wizard"):
        cmd_wizard(args)
    elif args.cmd == "check-env":
        cmd_check_env(args)
    elif args.cmd == "run":
        print(BANNER)
        topo = auto_detect_topology()
        cfg = _build_default_cfg(args, topo)
        run_audit_pipeline(cfg)
    elif args.cmd == "render":
        print(BANNER)
        render_existing_audit(
            args.audit_dir,
            compare_dirs=args.compare,
            build_pdf=not args.no_pdf,
            build_social=not args.no_social,
            opsec_bans=args.opsec_ban,
        )
    elif args.cmd == "verify":
        cmd_verify(args)


if __name__ == "__main__":
    main()

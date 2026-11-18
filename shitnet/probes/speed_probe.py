import csv
import json
import re
import statistics
import subprocess
from datetime import datetime, timezone
from ..targets import FASTLY_POP_THRESHOLDS, SPEED_TARGETS
from . import capture_pcap


def curl_transfer(url, host, port, ip, rng=None, max_time=18, source_ip=None):
    cmd = [
        "curl", "-4", "-L", "-sS", "-k", "-A", "Mozilla/5.0",
        "--max-time", str(max_time),
        "--resolve", f"{host}:{port}:{ip}",
        "-o", "/dev/null",
        "-w", "%{http_code} %{size_download} %{speed_download} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}",
    ]
    if source_ip:
        cmd += ["--interface", source_ip]
    if rng:
        cmd += ["-r", rng]
    cmd.append(url)
    p = subprocess.run(cmd, capture_output=True, text=True)
    parts = p.stdout.strip().split()
    if len(parts) == 7:
        code, sz, spd, tc, ta, ttfb, tt = parts
        return {
            "rc": p.returncode,
            "http_code": int(code) if code.isdigit() else 0,
            "bytes": int(float(sz)),
            "mbps": round((float(spd) * 8.0) / 1_000_000.0, 2),
            "connect_s": round(float(tc), 3),
            "tls_s": round(float(ta), 3),
            "ttfb_s": round(float(ttfb), 3),
            "total_s": round(float(tt), 3),
            "err": p.stderr.strip()[:140],
        }
    return {"rc": p.returncode, "http_code": 0, "bytes": 0, "mbps": 0.0, "connect_s": 0.0, "tls_s": 0.0, "ttfb_s": 0.0, "total_s": 0.0, "err": p.stderr.strip()[:140]}


def ping_burst(ip, count=40, source_ip=None):
    cmd = ["ping", "-n", "-i", "0.2", "-c", str(count), "-W", "2"]
    if source_ip:
        cmd += ["-I", source_ip]
    cmd.append(ip)
    p = subprocess.run(cmd, capture_output=True, text=True)
    rtts = [float(x) for x in re.findall(r"time=([\d.]+)\s*ms", p.stdout)]
    loss = 100.0
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", p.stdout)
    if m:
        loss = float(m.group(1))
    stats = {"sent": count, "recv": len(rtts), "loss_pct": loss, "min_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None, "stdev_ms": None}
    if rtts:
        s = sorted(rtts)
        stats["min_ms"] = round(s[0], 2)
        stats["p50_ms"] = round(statistics.median(s), 2)
        stats["p95_ms"] = round(s[min(len(s) - 1, int(0.95 * len(s)))], 2)
        stats["max_ms"] = round(s[-1], 2)
        stats["stdev_ms"] = round(statistics.stdev(s), 2) if len(s) > 1 else 0.0
    return stats


def build_jitter_hosts(gw_ip):
    hosts = []
    if gw_ip:
        hosts.append(("Local-GW", gw_ip))
    hosts.extend([
        ("Cloudflare-1.1.1.1", "1.1.1.1"),
        ("Google-8.8.8.8", "8.8.8.8"),
        ("Hetzner-FSN1", "78.46.170.2"),
        ("Fastly-POP2", "151.101.130.132"),
        ("IR-Domestic", "185.147.179.11"),
    ])
    return hosts


def run_isp_phase(pcap_dir, isp_iface, src_ip, gw_ip, progress_cb=None):
    pcap_path = pcap_dir / "05_speed_thresholds.pcapng"
    jitter_hosts = build_jitter_hosts(gw_ip)

    with capture_pcap(isp_iface, pcap_path, snaplen=192, progress_cb=progress_cb):
        speed_rows = []
        for idx, (label, url, host, port, ip, rng, mt) in enumerate(SPEED_TARGETS):
            if progress_cb:
                progress_cb(f"[Stage 5/6 Speed] Benchmark {idx + 1}/{len(SPEED_TARGETS)}: {label}...")
            isp = curl_transfer(url, host, port, ip, rng=rng, max_time=mt, source_ip=src_ip)
            speed_rows.append({"label": label, "url": url, "host": host, "port": port, "ip": ip, "rng": rng, "mt": mt, "isp": isp})

        if progress_cb:
            progress_cb("[Stage 5/6 Speed] Testing Fastly byte thresholds & burst jitter...")
        fastly_thresholds = []
        for ip, ranges in FASTLY_POP_THRESHOLDS:
            for scheme, port in [("http", 80), ("https", 443)]:
                use_ranges = ranges if scheme == "http" else [None, "0-4095", "0-20479"]
                for rng in use_ranges:
                    url = f"{scheme}://deb.debian.org/debian/dists/stable/Release"
                    isp = curl_transfer(url, "deb.debian.org", port, ip, rng=rng, max_time=10, source_ip=src_ip)
                    fastly_thresholds.append({"ip": ip, "scheme": scheme, "port": port, "range": rng or "FULL", "raw_range": rng, "isp": isp})

        jitter_rows = []
        for label, ip in jitter_hosts:
            isp_j = ping_burst(ip, count=40, source_ip=src_ip)
            jitter_rows.append({"label": label, "ip": ip, "isp": isp_j})

    return {
        "speed_benchmarks": speed_rows,
        "fastly_thresholds": fastly_thresholds,
        "jitter_bursts": jitter_rows,
    }


def run_control_phase(isp_state, gw_ip, has_control=True, progress_cb=None):
    speed_rows = []
    for r in isp_state["speed_benchmarks"]:
        if progress_cb and has_control:
            progress_cb(f"[Stage 5/6 Speed Control] Verifying {r['label']}...")
        ctl = curl_transfer(r["url"], r["host"], r["port"], r["ip"], rng=r["rng"], max_time=r["mt"], source_ip=None) if has_control else None
        speed_rows.append({"label": r["label"], "host": r["host"], "ip": r["ip"], "isp": r["isp"], "control": ctl})

    fastly_thresholds = []
    for f_row in isp_state["fastly_thresholds"]:
        ctl = None
        if has_control and f_row["raw_range"] in (None, "0-4095"):
            url = f"{f_row['scheme']}://deb.debian.org/debian/dists/stable/Release"
            ctl = curl_transfer(url, "deb.debian.org", f_row["port"], f_row["ip"], rng=f_row["raw_range"], max_time=10, source_ip=None)
        fastly_thresholds.append({"ip": f_row["ip"], "scheme": f_row["scheme"], "range": f_row["range"], "isp": f_row["isp"], "control": ctl})

    jitter_rows = []
    for j in isp_state["jitter_bursts"]:
        is_local = (gw_ip and j["ip"] == gw_ip) or j["ip"].startswith(("192.168.", "10.", "172.16."))
        ctl_j = ping_burst(j["ip"], count=20, source_ip=None) if (has_control and not is_local) else None
        jitter_rows.append({"label": j["label"], "ip": j["ip"], "isp": j["isp"], "control": ctl_j})

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "has_control": has_control,
        "speed_benchmarks": speed_rows,
        "fastly_thresholds": fastly_thresholds,
        "jitter_bursts": jitter_rows,
    }


def save_outputs(raw_dir, data):
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "05_throughput_jitter_forensics.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    with (raw_dir / "05_speed_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "ip", "isp_rc", "isp_http", "isp_bytes", "isp_mbps", "isp_ttfb_s", "control_rc", "control_http", "control_bytes", "control_mbps"])
        for r in data["speed_benchmarks"]:
            ctl = r.get("control") or {}
            w.writerow([
                r["label"], r["ip"],
                r["isp"]["rc"], r["isp"]["http_code"], r["isp"]["bytes"], r["isp"]["mbps"], r["isp"]["ttfb_s"],
                ctl.get("rc", ""), ctl.get("http_code", ""), ctl.get("bytes", ""), ctl.get("mbps", ""),
            ])

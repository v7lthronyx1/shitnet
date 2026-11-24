import csv
import json
import socket
import subprocess
import time
from datetime import datetime, timezone
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import requests
from ..netenv import bind_socket, detect_isp_identity, derive_connection_type, fetch_public_ip, is_private_or_reserved
from ..targets import DOMAINS, FALLBACK_DOMAIN_IPS, STATIC_RESOLVERS
from . import capture_pcap, resolve_control_host


def query_dns(server_ip, domain, rtype="A", port=53, proto="udp", source_ip=None, timeout=1.6, dnssec=False, iface=None):
    res = {
        "ok": False,
        "rcode": None,
        "ips": [],
        "cnames": [],
        "other": [],
        "ttl": None,
        "rtt_ms": None,
        "aa": False,
        "ra": False,
        "ad": False,
        "has_rrsig": False,
        "error": None,
    }
    s = None
    try:
        q = dns.message.make_query(domain, rtype, use_edns=0, want_dnssec=dnssec)
        t0 = time.monotonic()
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            bind_socket(s, source_ip=source_ip, iface=iface)
            s.sendto(q.to_wire(), (server_ip, port))
            wire, _ = s.recvfrom(4096)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            bind_socket(s, source_ip=source_ip, iface=iface)
            s.connect((server_ip, port))
            payload = q.to_wire()
            s.sendall(len(payload).to_bytes(2, "big") + payload)
            hdr = b""
            while len(hdr) < 2:
                chunk = s.recv(2 - len(hdr))
                if not chunk:
                    raise EOFError("short tcp dns len")
                hdr += chunk
            need = int.from_bytes(hdr, "big")
            wire = b""
            while len(wire) < need:
                chunk = s.recv(need - len(wire))
                if not chunk:
                    raise EOFError("short tcp dns body")
                wire += chunk
        dt = round((time.monotonic() - t0) * 1000.0, 2)
        ans = dns.message.from_wire(wire)
        res["ok"] = True
        res["rtt_ms"] = dt
        res["rcode"] = dns.rcode.to_text(ans.rcode())
        res["aa"] = bool(ans.flags & dns.flags.AA)
        res["ra"] = bool(ans.flags & dns.flags.RA)
        res["ad"] = bool(ans.flags & dns.flags.AD)
        for rrset in ans.answer:
            if res["ttl"] is None:
                res["ttl"] = rrset.ttl
            if rrset.rdtype == dns.rdatatype.RRSIG:
                res["has_rrsig"] = True
            for item in rrset:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    res["ips"].append(item.address)
                elif rrset.rdtype == dns.rdatatype.CNAME:
                    res["cnames"].append(str(item.target))
                else:
                    res["other"].append(item.to_text())
    except PermissionError as e:
        res["error"] = f"HOST_SOCKET_EPERM: {e}"
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def doh_direct_query(domain, source_ip=None, timeout=2.5, iface=None):
    bind_dev = iface or source_ip
    for srv_ip in ("1.1.1.1", "9.9.9.9"):
        cmd = [
            "curl", "-4", "-sS", "-k", "--max-time", str(timeout),
            "-H", "Accept: application/dns-json",
        ]
        if bind_dev:
            cmd += ["--interface", bind_dev]
        cmd.append(f"https://{srv_ip}/dns-query?name={domain}&type=A")
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            try:
                data = json.loads(p.stdout)
                ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                if ips:
                    return {"ok": True, "rcode": "NOERROR", "ips": ips}
            except Exception:
                pass
    return {"ok": False, "rcode": None, "ips": []}


def classify_dns(isp_a, ctl_a):
    if not isp_a["ok"]:
        return "ISP_DNS_ERROR"
    if isp_a["rcode"] == "NXDOMAIN" and ctl_a and ctl_a.get("ok") and ctl_a.get("ips"):
        return "NXDOMAIN_BLOCK"
    ips = set(isp_a["ips"])
    ctl_ips = set((ctl_a or {}).get("ips") or [])
    if any(ip in ips for ip in ("10.10.34.34", "10.10.34.35", "10.10.34.36")):
        return "SINKHOLE_10_10_34_X"
    if "216.239.38.120" in ips and "216.239.38.120" not in ctl_ips:
        return "FORCED_SAFESEARCH"
    if any(is_private_or_reserved(ip) for ip in ips):
        return "PRIVATE_RFC1918_REDIRECT"
    if isp_a["ips"]:
        return "CLEAN_OR_REAL_IP"
    return f"EMPTY_{isp_a['rcode']}"


def run_isp_phase(raw_dir, pcap_dir, isp_iface, src_ip, gw_dns, domains=None, resolvers=None, conn_type=None, operator_override=None, progress_cb=None):
    domains = domains or DOMAINS
    gw_ip = gw_dns
    if not gw_ip:
        gw_ip = "192.168.1.1"
    probe_list = [("ISP-GW-DNS", gw_ip, 53, "udp")] + list(resolvers or STATIC_RESOLVERS)

    pcap_path = pcap_dir / "01_dns_forensics.pcapng"
    with capture_pcap(isp_iface, pcap_path, snaplen=512, progress_cb=progress_cb):
        isp_public_ip = fetch_public_ip(source_ip=src_ip, iface=isp_iface)
        whoami = query_dns(gw_ip, "whoami.akamai.net", "TXT", 53, "udp", source_ip=src_ip, iface=isp_iface)

        resolver_matrix = []
        probe_domains = [("x.com", "A"), ("youtube.com", "A"), ("google.com", "A"), ("pages.dev", "A"), ("deb.debian.org", "A"), ("cloudflare.com", "A")]
        for label, srv, port, proto in probe_list:
            entry = {"label": label, "server": srv, "port": port, "proto": proto, "results": {}}
            for dom, rt in probe_domains:
                entry["results"][dom] = query_dns(srv, dom, rt, port, proto, source_ip=src_ip, timeout=1.6, iface=isp_iface)
            resolver_matrix.append(entry)

        isp_domain_rows = []
        for idx, (cat, dom) in enumerate(domains):
            if progress_cb and idx % 25 == 0:
                progress_cb(f"[Stage 1/6 DNS] Probing {idx + 1}/{len(domains)} on ISP...")
            isp_a = query_dns(gw_ip, dom, "A", 53, "udp", source_ip=src_ip, iface=isp_iface)
            isp_quad9 = query_dns("9.9.9.9", dom, "A", 53, "udp", source_ip=src_ip, timeout=1.5, iface=isp_iface)
            isp_114 = query_dns("114.114.114.114", dom, "A", 53, "udp", source_ip=src_ip, timeout=1.5, iface=isp_iface) if cat in ("search_infra", "cloud_dev_cdn", "social_video") else None
            isp_aaaa = query_dns(gw_ip, dom, "AAAA", 53, "udp", source_ip=src_ip, iface=isp_iface)
            isp_https = query_dns(gw_ip, dom, "HTTPS", 53, "udp", source_ip=src_ip, iface=isp_iface)
            isp_dnssec = query_dns(gw_ip, dom, "A", 53, "udp", source_ip=src_ip, dnssec=True, iface=isp_iface)
            isp_domain_rows.append({
                "category": cat,
                "domain": dom,
                "isp_gw_a": isp_a,
                "isp_quad9_a": isp_quad9,
                "isp_114_a": isp_114,
                "isp_gw_aaaa": isp_aaaa,
                "isp_gw_https": isp_https,
                "isp_dnssec": {"ad": isp_dnssec["ad"], "has_rrsig": isp_dnssec["has_rrsig"]},
            })

    identity = detect_isp_identity(isp_public_ip, meta_source_ip=src_ip, operator_override=operator_override, meta_iface=isp_iface)
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "network_identity": {
            "interface": isp_iface,
            "connection_type": derive_connection_type(isp_iface, conn_type),
            "src_ip": src_ip,
            "gw_ip": gw_ip,
            "isp_public_ip": isp_public_ip,
            "control_public_ip": "",
            "asn": identity["asn"],
            "prefix": identity["prefix"],
            "operator": identity["operator"],
            "ipinfo": identity["ipinfo"],
            "ripe_prefix_overview": identity["ripe_prefix_overview"],
            "whoami_akamai_gw": whoami,
        },
        "resolver_probes": resolver_matrix,
        "isp_domains": isp_domain_rows,
    }


def run_control_phase(isp_state, control_dns="1.1.1.1", has_control=True, operator_override=None, progress_cb=None):
    isp_ip = isp_state["network_identity"]["isp_public_ip"]
    if has_control:
        ctl_ip = fetch_public_ip(source_ip=None)
        isp_state["network_identity"]["control_public_ip"] = ctl_ip
        if isp_ip and (not isp_state["network_identity"]["ipinfo"] or "error" in isp_state["network_identity"]["ipinfo"]):
            refreshed = detect_isp_identity(isp_ip, meta_source_ip=None, operator_override=operator_override)
            isp_state["network_identity"].update({
                "asn": refreshed["asn"],
                "prefix": refreshed["prefix"],
                "operator": refreshed["operator"],
                "ipinfo": refreshed["ipinfo"],
                "ripe_prefix_overview": refreshed["ripe_prefix_overview"],
            })

    domain_rows = []
    isp_list = isp_state["isp_domains"]
    for idx, row in enumerate(isp_list):
        dom = row["domain"]
        if progress_cb and idx % 25 == 0:
            progress_cb(f"[Stage 1/6 DNS Control] Resolving {idx + 1}/{len(isp_list)}...")
        if has_control:
            ctl_a = query_dns(control_dns, dom, "A", 53, "udp", source_ip=None, timeout=2.0)
            if not ctl_a["ips"]:
                fb = resolve_control_host(dom, control_dns=control_dns)
                if fb:
                    ctl_a["ok"] = True
                    ctl_a["rcode"] = "NOERROR"
                    ctl_a["ips"] = fb
            ctl_https = query_dns(control_dns, dom, "HTTPS", 53, "udp", source_ip=None, timeout=2.0)
            ctl_dnssec = query_dns(control_dns, dom, "A", 53, "udp", source_ip=None, timeout=2.0, dnssec=True)
            ctl_https_count = len(ctl_https["other"])
            ctl_dnssec_meta = {"ad": ctl_dnssec["ad"], "has_rrsig": ctl_dnssec["has_rrsig"]}
        else:
            fb_ips = FALLBACK_DOMAIN_IPS.get(dom, [])
            ctl_a = {"ok": bool(fb_ips), "rcode": "NOERROR" if fb_ips else None, "ips": list(fb_ips), "cnames": [], "other": [], "ttl": None, "rtt_ms": None, "aa": False, "ra": False, "ad": False, "has_rrsig": False, "error": None}
            ctl_https_count = 0
            ctl_dnssec_meta = {"ad": False, "has_rrsig": False}

        verdict = classify_dns(row["isp_gw_a"], ctl_a)
        q9_verdict = classify_dns(row["isp_quad9_a"], ctl_a)
        domain_rows.append({
            "category": row["category"],
            "domain": dom,
            "verdict_gw": verdict,
            "verdict_quad9_intercept": q9_verdict,
            "isp_gw_a": row["isp_gw_a"],
            "isp_quad9_a": row["isp_quad9_a"],
            "isp_114_a": row["isp_114_a"],
            "isp_gw_aaaa": row["isp_gw_aaaa"],
            "isp_gw_https": row["isp_gw_https"],
            "isp_dnssec": row["isp_dnssec"],
            "control_a": ctl_a,
            "control_https_count": ctl_https_count,
            "control_dnssec": ctl_dnssec_meta,
        })

    return {
        "timestamp_utc": isp_state["timestamp_utc"],
        "has_control": has_control,
        "network_identity": isp_state["network_identity"],
        "resolver_probes": isp_state["resolver_probes"],
        "domains_count": len(domain_rows),
        "domains": domain_rows,
    }


def save_outputs(raw_dir, data):
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "01_deep_dns_forensics.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    with (raw_dir / "01_dns_matrix.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "domain", "verdict_gw", "verdict_quad9", "isp_ips", "quad9_ips", "control_ips", "isp_rtt_ms", "isp_aaaa_ips", "isp_https_cnt", "control_https_cnt", "isp_rrsig", "control_rrsig"])
        for r in data["domains"]:
            w.writerow([
                r["category"],
                r["domain"],
                r["verdict_gw"],
                r["verdict_quad9_intercept"],
                ";".join(r["isp_gw_a"]["ips"]),
                ";".join(r["isp_quad9_a"]["ips"]),
                ";".join(r["control_a"]["ips"]),
                r["isp_gw_a"]["rtt_ms"],
                ";".join(r["isp_gw_aaaa"]["ips"]),
                len(r["isp_gw_https"]["other"]),
                r["control_https_count"],
                r["isp_dnssec"]["has_rrsig"],
                r["control_dnssec"]["has_rrsig"],
            ])

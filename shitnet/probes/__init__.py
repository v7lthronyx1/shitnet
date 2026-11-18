import contextlib
import shutil
import subprocess
import time
import dns.message
import dns.rdatatype
import requests


@contextlib.contextmanager
def capture_pcap(iface, pcap_path, snaplen=512, progress_cb=None):
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    if pcap_path.exists():
        pcap_path.unlink()
    dumpcap_bin = shutil.which("dumpcap")
    proc = None
    if dumpcap_bin and iface:
        try:
            proc = subprocess.Popen(
                [dumpcap_bin, "-i", iface, "-s", str(snaplen), "-q", "-w", str(pcap_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.2)
            if proc.poll() is not None:
                err = proc.stderr.read().decode("utf-8", "replace").strip() if proc.stderr else ""
                if progress_cb:
                    progress_cb(f"[warn] dumpcap exited early on {iface}: {err}")
                proc = None
        except Exception as e:
            if progress_cb:
                progress_cb(f"[warn] dumpcap skipped: {e}")
            proc = None
    try:
        yield pcap_path
    finally:
        if proc is not None:
            time.sleep(0.8)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


def resolve_control_host(host, control_dns="1.1.1.1"):
    try:
        import socket
        socket.inet_aton(host)
        return [host]
    except OSError:
        pass
    import socket
    for dns_srv in [control_dns, "1.1.1.1", "8.8.8.8"]:
        if not dns_srv:
            continue
        s = None
        try:
            q = dns.message.make_query(host, "A").to_wire()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.2)
            s.sendto(q, (dns_srv, 53))
            wire, _ = s.recvfrom(4096)
            ans = dns.message.from_wire(wire)
            ips = []
            for rrset in ans.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    ips.extend([item.address for item in rrset])
            if ips:
                return ips
        except Exception:
            pass
        finally:
            if s:
                s.close()
    try:
        r = requests.get(
            f"https://1.1.1.1/dns-query?name={host}&type=A",
            headers={"Accept": "application/dns-json"},
            timeout=3.5,
        )
        data = r.json()
        ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
        if ips:
            return ips
    except Exception:
        pass
    return []

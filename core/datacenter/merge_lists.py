#!/usr/bin/env python3
"""Merge datacenter/VPN CIDR lists into one deduped, sorted set for embedding."""
import json, sys, ipaddress, urllib.request

BASE = r"C:\Users\Administrator\Desktop\evilginx2-master\core\datacenter"

def load_file(path):
    nets = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    return nets

def fetch(url, timeout=90):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

def fetch_json(url):
    return json.loads(fetch(url))

all_v4, all_v6 = [], []
src_counts = {}

def add(name, nets):
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    src_counts[name] = {"v4": len(v4), "v6": len(v6)}
    all_v4.extend(v4); all_v6.extend(v6)
    print(f"{name}: v4={len(v4)} v6={len(v6)}")

# 1. X4BNet (VPN + datacenter)
add("x4bnet", load_file(f"{BASE}\\datacenter-ipv4.txt") + load_file(f"{BASE}\\datacenter-ipv6.txt"))

# 2. jhassine server-ip-addresses (txt + csv)
_j = load_file(f"{BASE}\\jhassine-ipv4.txt")
with open(f"{BASE}\\datacenters.csv", encoding="utf-8", errors="ignore") as f:
    import csv as _csv
    for row in _csv.DictReader(f):
        try:
            _j.append(ipaddress.ip_network(row["cidr"], strict=False))
        except (ValueError, KeyError):
            pass
add("jhassine", _j)

# 3. AWS official
try:
    d = fetch_json("https://ip-ranges.amazonaws.com/ip-ranges.json")
    add("aws", [ipaddress.ip_network(p["ip_prefix"]) for p in d.get("prefixes", [])] +
                [ipaddress.ip_network(p["ipv6_prefix"]) for p in d.get("ipv6_prefixes", [])])
except Exception as e:
    print(f"aws FAILED: {e}", file=sys.stderr)

# 4. GCP official
try:
    d = fetch_json("https://www.gstatic.com/ipranges/cloud.json")
    add("gcp", [ipaddress.ip_network(p["ipv4Prefix"]) for p in d.get("prefixes", []) if "ipv4Prefix" in p] +
                [ipaddress.ip_network(p["ipv6Prefix"]) for p in d.get("prefixes", []) if "ipv6Prefix" in p])
except Exception as e:
    print(f"gcp FAILED: {e}", file=sys.stderr)

# 5. Azure official (ServiceTags — downloaded from MS download center page)
try:
    with open(f"{BASE}\\azure-servicetags.json", encoding="utf-8") as f:
        d = json.load(f)
    nets = []
    for _, vals in d.get("values", {}).items():
        for p in vals.get("properties", {}).get("addressPrefixes", []):
            try:
                nets.append(ipaddress.ip_network(p))
            except ValueError:
                pass
    add("azure", nets)
except Exception as e:
    print(f"azure FAILED: {e}", file=sys.stderr)

# 6. Manual extras — ranges confirmed missing from all feeds above
#    (CloudBlast AS207847 — user's own datacenter, verified missing)
add("extras", [
    ipaddress.ip_network("192.166.82.0/24"),   # CloudBlast AS207847
    ipaddress.ip_network("172.104.0.0/16"),    # Linode gap
    ipaddress.ip_network("149.28.0.0/16"),      # Vultr gap
    ipaddress.ip_network("34.64.0.0/16"),      # GCP AS139070 gap
])

# Collapse overlaps/dedupe via network aggregation
def collapse(nets):
    # ipaddress.collapse_addresses handles merge/dedupe efficiently
    return list(ipaddress.collapse_addresses(nets))

v4 = collapse(all_v4)
v6 = collapse(all_v6)

with open(f"{BASE}\\merged-ipv4.txt", "w") as f:
    f.write("\n".join(str(n) for n in v4) + "\n")
with open(f"{BASE}\\merged-ipv6.txt", "w") as f:
    f.write("\n".join(str(n) for n in v6) + "\n")

print("\n=== SOURCES ===")
for k, v in src_counts.items():
    print(f"  {k}: {v}")
print(f"=== MERGED (deduped/collapsed): v4={len(v4)} v6={len(v6)} ===")

# Sanity: verify knowns
def check(ip):
    a = ipaddress.ip_address(ip)
    pool = v4 if a.version == 4 else v6
    return any(a in n for n in pool)
for ip in ["192.166.82.81", "172.104.1.1", "149.28.1.1", "34.64.1.1", "104.248.1.1", "52.1.1.1", "13.64.1.1", "45.32.1.1"]:
    print(f"  {ip}: {'BLOCKED' if check(ip) else 'PASS'}")
for ip in ["81.202.1.1", "24.1.1.1", "98.1.1.1", "82.11.1.1", "217.45.1.1"]:
    print(f"  {ip}: {'BLOCKED(!)' if check(ip) else 'PASS'}")

import json
import random

ASSET_FILE = "enterprise_assets.json"
OUTPUT_FILE = "network_sbom.json"


# 🔹 Load assets
with open(ASSET_FILE, "r") as f:
    assets = json.load(f)


# 🔹 Subnets
SUBNETS = [
    {"subnet_id": "DMZ", "cidr": "10.0.1.0/24", "type": "internet-facing"},
    {"subnet_id": "APP", "cidr": "10.0.2.0/24", "type": "internal"},
    {"subnet_id": "DB", "cidr": "10.0.3.0/24", "type": "restricted"}
]


# 🔹 Dependency pool (SBOM)
DEPENDENCIES = {
    "apache": ["openssl", "pcre", "zlib"],
    "nginx": ["openssl", "pcre"],
    "php": ["openssl", "libxml"],
    "nodejs": ["openssl", "libuv"],
    "mysql": ["openssl"],
    "mongodb": ["openssl"],
    "python": ["pip", "setuptools"],
    "docker": ["containerd"],
    "openssl": [],
    "nmap": ["libpcap"],
    "wireshark": ["libpcap"],
}


# 🔹 Assign subnet based on role/software
def assign_subnet(asset):
    software_names = [s["name"] for s in asset["software"]]

    if "apache" in software_names or "nginx" in software_names:
        return "DMZ"
    elif "mysql" in software_names or "mongodb" in software_names:
        return "DB"
    else:
        return "APP"


# 🔹 Generate SBOM
def generate_sbom(asset):
    sbom = []

    used = set()

    for sw in asset["software"]:
        name = sw["name"]

        deps = DEPENDENCIES.get(name, [])

        for d in deps:
            if d not in used:
                used.add(d)
                sbom.append({
                    "component": d,
                    "version": "unknown"
                })

    return sbom


# 🔹 Generate connections (low repetition)
def generate_connections(assets):
    connections = []

    for i in range(len(assets)):
        src = assets[i]

        # connect only to 1–2 assets
        targets = random.sample(assets, random.randint(1, 2))

        for tgt in targets:
            if src["asset_id"] != tgt["asset_id"]:
                connections.append({
                    "source": src["asset_id"],
                    "target": tgt["asset_id"],
                    "protocol": random.choice(["HTTP", "SSH", "TCP"])
                })

    return connections


# 🔹 Build final dataset
network_data = {
    "subnets": SUBNETS,
    "assets": [],
    "connections": generate_connections(assets)
}


for asset in assets:
    network_data["assets"].append({
        "asset_id": asset["asset_id"],
        "subnet": assign_subnet(asset),
        "sbom": generate_sbom(asset)
    })


# 🔹 Save
with open(OUTPUT_FILE, "w") as f:
    json.dump(network_data, f, indent=2)


print("✅ Network Topology + SBOM generated successfully")
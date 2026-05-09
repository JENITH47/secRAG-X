import json
import random

OUTPUT_FILE = "enterprise_assets.json"
NUM_ASSETS = 50  # 🔥 change as needed


# 🔹 OS (also used as software)
OS_LIST = [
    ("windows server", ["2016", "2019"]),
    ("windows", ["10"]),
    ("ubuntu", ["20.04", "22.04"])
]


# 🔹 Software pool (CPE-friendly names)
SOFTWARE_POOL = [
    ("apache", ["2.4.54", "2.4.57"]),
    ("nginx", ["1.18.0", "1.22.0"]),
    ("mysql", ["5.7", "8.0"]),
    ("mongodb", ["4.4", "5.0"]),
    ("php", ["7.4", "8.1"]),
    ("nodejs", ["14.0", "16.0"]),
    ("openssl", ["1.1.1", "3.0"]),
    ("nmap", ["7.80", "7.93"]),
    ("docker", ["20.10", "24.0"]),
    ("python", ["3.8", "3.9", "3.10"]),
    ("wireshark", ["3.6", "4.0"]),
    ("microsoft sql server", ["2016", "2019"])
]


DEPARTMENTS = ["IT", "Engineering", "Security", "Database", "DevOps"]


# 🔹 Controlled criticality distribution
CRITICALITY_POOL = (
    ["CRITICAL"] * 2 +
    ["HIGH"] * 3 +
    ["MEDIUM"] * 3 +
    ["LOW"] * 2
)


def generate_ip(index):
    return f"192.168.1.{index+10}"


def normalize_name(name):
    return name.replace(".", "").replace("-", "").lower().strip()


def generate_asset(index):
    hostname = f"asset-{index+1}"

    # 🔹 Select OS
    os_name, os_versions = random.choice(OS_LIST)
    os_version = random.choice(os_versions)

    # 🔹 Select software (no repetition)
    software_count = random.randint(2, 4)
    selected_software = random.sample(SOFTWARE_POOL, software_count)

    software_list = []

    # 🔥 Add OS as software (VERY IMPORTANT)
    software_list.append({
        "name": normalize_name(os_name),
        "version": os_version
    })

    # 🔹 Add other software
    for name, versions in selected_software:
        software_list.append({
            "name": normalize_name(name),
            "version": random.choice(versions)
        })

    return {
        "asset_id": f"SRV-{str(index+1).zfill(3)}",
        "hostname": hostname,
        "ip": generate_ip(index),
        "os": f"{os_name} {os_version}",
        "software": software_list,
        "department": random.choice(DEPARTMENTS),
        "criticality": random.choice(CRITICALITY_POOL)
    }


# 🔹 Generate dataset
assets = [generate_asset(i) for i in range(NUM_ASSETS)]


# 🔹 Save
with open(OUTPUT_FILE, "w") as f:
    json.dump(assets, f, indent=2)


print(f"✅ Generated {NUM_ASSETS} improved enterprise assets")
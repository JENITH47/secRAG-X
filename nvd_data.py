import json

INPUT_FILE = "nvdcve-2.0-2024.json"
OUTPUT_FILE = "clean_cve_final-2024.json"


# 🔹 Normalize text
def normalize_text(text):
    return text.replace("_", " ").lower().strip()


# 🔹 Parse CPE
def parse_cpe(cpe_string):
    parts = cpe_string.split(":")

    if len(parts) < 6:
        return None

    version = parts[5]

    if version == "*":
        version = "all"
    elif version in ["-", ""]:
        version = "unspecified"

    return {
        "vendor": normalize_text(parts[3]),
        "product": normalize_text(parts[4]),
        "version": version
    }


# 🔹 Attack type mapping (YOUR TAXONOMY)
ATTACK_MAP = {
    # Injection
    "sql injection": "SQL Injection",
    "xss": "XSS",
    "cross site scripting": "XSS",
    "command injection": "Command Injection",
    "xxe": "XXE Injection",
    "xml injection": "XXE Injection",
    "ssti": "SSTI",
    "csv injection": "CSV Injection",

    # Memory
    "buffer overflow": "Buffer Overflow",
    "out-of-bounds": "Out-of-Bounds",
    "use-after-free": "Use After Free",
    "null pointer": "Null Pointer Dereference",
    "integer overflow": "Integer Overflow",

    # Auth
    "privilege escalation": "Privilege Escalation",
    "authentication bypass": "Auth Bypass",
    "idor": "IDOR",
    "session hijacking": "Session Hijacking",
    "hard-coded": "Hardcoded Credentials",

    # File
    "path traversal": "Path Traversal",
    "file upload": "File Upload",
    "lfi": "File Inclusion",
    "rfi": "File Inclusion",
    "dll hijacking": "DLL Hijacking",

    # Network
    "csrf": "CSRF",
    "ssrf": "SSRF",
    "man in the middle": "MITM",

    # Crypto
    "plaintext": "Weak Crypto",
    "weak hash": "Weak Crypto",

    # Availability
    "denial of service": "DoS",
    "dos": "DoS",
    "resource exhaustion": "Resource Exhaustion",

    # Misc
    "deserialization": "Deserialization",
    "race condition": "Race Condition",
    "information disclosure": "Information Disclosure",
    "sensitive information": "Information Disclosure",
    "clickjacking": "Clickjacking"
}


# 🔹 Extract attack type
def extract_attack_type(desc):
    desc = desc.lower()

    for key, value in ATTACK_MAP.items():
        if key in desc:
            return value

    return "Other"


# 🔹 Extract CWE
def extract_cwe(cve):
    cwe_list = []

    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("value", "").startswith("CWE"):
                cwe_list.append(desc.get("value"))

    return list(set(cwe_list))


# 🔹 Extract CVSS details
def extract_metrics(metrics):
    attack_vector = "UNKNOWN"
    privileges_required = "UNKNOWN"
    user_interaction = "UNKNOWN"
    severity = "UNKNOWN"
    score = 0

    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]

        severity = cvss.get("baseSeverity", "UNKNOWN")
        score = cvss.get("baseScore", 0)
        attack_vector = cvss.get("attackVector", "UNKNOWN")
        privileges_required = cvss.get("privilegesRequired", "UNKNOWN")
        user_interaction = cvss.get("userInteraction", "UNKNOWN")

    return severity, score, attack_vector, privileges_required, user_interaction


# 🔹 Clean CPE list
def clean_cpe_list(cpe_list):
    cleaned = []
    seen = set()

    for c in cpe_list:
        key = (c["vendor"], c["product"], c["version"])

        if key not in seen:
            seen.add(key)
            cleaned.append(c)

    return cleaned


# 🔹 Main extraction
def extract_cve_data(data):
    results = []

    for item in data["vulnerabilities"]:

        cve = item["cve"]

        cve_id = cve.get("id")
        published = cve.get("published")

        # Description
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value")
                break

        # ❌ Skip rejected
        if "rejected" in description.lower():
            continue

        # Metrics
        severity, score, attack_vector, privileges_required, user_interaction = extract_metrics(
            cve.get("metrics", {})
        )

        # CWE
        cwe_list = extract_cwe(cve)

        # CPE
        cpe_list = []
        seen = set()

        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):

                    if match.get("vulnerable"):
                        parsed = parse_cpe(match.get("criteria"))

                        if parsed:
                            key = (parsed["vendor"], parsed["product"], parsed["version"])

                            if key not in seen:
                                seen.add(key)
                                cpe_list.append(parsed)

        if not cpe_list:
            continue

        # Final output
        results.append({
            "cve_id": cve_id,
            "published": published,
            "description": description,
            "severity": severity,
            "cvss_score": score,
            "attack_type": extract_attack_type(description),
            "cwe": cwe_list,
            "attack_vector": attack_vector,
            "privileges_required": privileges_required,
            "user_interaction": user_interaction,
            "cpe": clean_cpe_list(cpe_list)
        })

    return results


# 🔹 FIX JSON loading issue
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    content = f.read()

end_index = content.rfind("}")
clean_content = content[:end_index + 1]

data = json.loads(clean_content)


# 🔹 Process
cleaned = extract_cve_data(data)


# 🔹 Save
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(cleaned, f, indent=2)


print(f"✅ FINAL DATASET READY: {len(cleaned)} CVEs")
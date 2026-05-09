import json

FILES = [
    "clean_cve_final-2024.json",
    "clean_cve_final-2025.json",
    "clean_cve_final-2026.json"
]

OUTPUT_FILE = "cleaned_cve.json"


all_cves = []
seen = set()

for file in FILES:
    print(f"📂 Loading {file}")

    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)

        for cve in data:
            cve_id = cve["cve_id"]

            # 🔥 remove duplicates
            if cve_id not in seen:
                seen.add(cve_id)
                all_cves.append(cve)


# 🔹 Save merged file
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(all_cves, f, indent=2)

print(f"✅ Merged {len(all_cves)} CVEs into {OUTPUT_FILE}")
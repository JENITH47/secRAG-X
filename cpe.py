import json
import os

INPUT_FOLDER = "nvdcpematch-2.0-chunks"
OUTPUT_FILE = "clean_cpe_dataset.json"


def normalize_text(text):
    return text.replace("_", " ").lower().strip()


def parse_cpe(cpe_uri):
    parts = cpe_uri.split(":")

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


def extract_cpe_data(data):
    results = []

    for item in data.get("matchStrings", []):

        match = item.get("matchString", {})

        cpe_uri = match.get("criteria")

        if not cpe_uri:
            continue

        parsed = parse_cpe(cpe_uri)

        if parsed:
            results.append(parsed)

    return results


def process_all_files():
    all_cpe = []
    seen = set()

    files = os.listdir(INPUT_FOLDER)

    print(f"📂 Found {len(files)} files")

    for file in files:
        if not file.endswith(".json"):
            continue

        path = os.path.join(INPUT_FOLDER, file)

        print(f"⚙️ Processing: {file}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            extracted = extract_cpe_data(data)

            for c in extracted:
                key = (c["vendor"], c["product"], c["version"])

                if key not in seen:
                    seen.add(key)
                    all_cpe.append(c)

        except Exception as e:
            print(f"❌ Error in {file}: {e}")

    return all_cpe


# 🔹 RUN
cleaned = process_all_files()

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(cleaned, f, indent=2)

print(f"✅ FINAL CPE DATASET READY: {len(cleaned)} entries")
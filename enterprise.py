import json

INPUT_FILE = "enterprise-attack.json"
OUTPUT_FILE = "clean_techniques.json"

def extract_techniques(data):
    techniques = []

    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern":

            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            technique = {
                "technique_id": technique_id,
                "name": obj.get("name"),
                "description": obj.get("description", "").strip(),
                "platforms": obj.get("x_mitre_platforms", []),

                # ✅ FIXED HERE
                
            }

            techniques.append(technique)

    return techniques


with open(INPUT_FILE, "r") as f:
    data = json.load(f)

cleaned = extract_techniques(data)

with open(OUTPUT_FILE, "w") as f:
    json.dump(cleaned, f, indent=2)

print(f"✅ Extracted {len(cleaned)} techniques")
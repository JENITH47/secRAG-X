import json

INPUT_FILE = "enterprise-attack.json"
OUTPUT_FILE = "technique_with_tactics.json"

def extract_techniques_with_tactics(data):
    results = []

    for obj in data["objects"]:

        if obj.get("type") == "attack-pattern":

            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            # ✅ Extract Technique ID
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            # 🔥 Fallback: use 'kill_chain_phases' if exists
            tactics = []

            if "kill_chain_phases" in obj:
                tactics = [
                    phase.get("phase_name")
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("phase_name")
                ]

            # If still empty → assign UNKNOWN (temporary fix)
            if not tactics:
                tactics = ["unknown"]

            results.append({
                "technique_id": technique_id,
                "name": obj.get("name"),
                "tactics": tactics
            })

    return results


with open(INPUT_FILE, "r") as f:
    data = json.load(f)

cleaned = extract_techniques_with_tactics(data)

with open(OUTPUT_FILE, "w") as f:
    json.dump(cleaned, f, indent=2)

print("✅ Done")
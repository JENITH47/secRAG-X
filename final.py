import json

INPUT_FILE = "enterprise-attack.json"
OUTPUT_FILE = "final_technique_data.json"

def format_tactic(tactic):
    return tactic.replace("-", " ").title()

def extract_all(data):
    techniques = {}
    mitigations = {}
    relationships = []

    # 🔹 Step 1: Extract Techniques + Tactics
    for obj in data["objects"]:

        # ✅ Techniques
        if obj.get("type") == "attack-pattern":

            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            tech_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")
                    break

            if not tech_id:
                continue

            tactics = [
                format_tactic(phase.get("phase_name"))
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("phase_name")
            ]

            techniques[obj["id"]] = {
                "technique_id": tech_id,
                "name": obj.get("name"),
                "tactics": tactics if tactics else ["Unknown"],
                "mitigations": []
            }

        # ✅ Mitigations
        elif obj.get("type") == "course-of-action":

            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            mitigations[obj["id"]] = obj.get("name")

        # ✅ Relationships
        elif obj.get("type") == "relationship":
            relationships.append(obj)

    # 🔹 Step 2: Map Mitigation → Technique
    for rel in relationships:

        if rel.get("relationship_type") != "mitigates":
            continue

        source = rel.get("source_ref")   # mitigation
        target = rel.get("target_ref")   # technique

        if source in mitigations and target in techniques:
            techniques[target]["mitigations"].append(mitigations[source])

    return list(techniques.values())


# 🔹 Load file
with open(INPUT_FILE, "r") as f:
    data = json.load(f)

# 🔹 Extract everything
cleaned = extract_all(data)

# 🔹 Save output
with open(OUTPUT_FILE, "w") as f:
    json.dump(cleaned, f, indent=2)

print("✅ Step 3 completed: Techniques + Tactics + Mitigations ready")
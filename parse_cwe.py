import xml.etree.ElementTree as ET
import json

tree = ET.parse("cwec_latest.xml/cwec_v4.19.1.xml")   # use your file name
root = tree.getroot()

# Extract namespace dynamically
ns = {'cwe': root.tag.split('}')[0].strip('{')}

cwe_list = []

# IMPORTANT: Weakness is inside Weaknesses tag
for weakness in root.findall(".//cwe:Weakness", ns):

    cwe_id = weakness.get("ID")
    name = weakness.get("Name")

    # Description handling (sometimes missing)
    desc_elem = weakness.find("cwe:Description", ns)
    description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

    if cwe_id and name:
        cwe_list.append({
            "cwe_id": f"CWE-{cwe_id}",
            "name": name,
            "description": description[:200]
        })

print("✅ Total CWE extracted:", len(cwe_list))

# Save file
with open("cleaned_cwe.json", "w", encoding="utf-8") as f:
    json.dump(cwe_list, f, indent=2)

print("✅ JSON created successfully")
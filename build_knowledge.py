import json
from pathlib import Path

from vector_store import build_vector_db


SAFE_GUIDANCE = [
    "A vulnerability means a known weakness in software. Employees do not need forensic tools; they should report concerns and let IT patch or configure the system.",
    "SQL Injection can affect systems that store or handle data. The simple action is to use trusted company apps and report suspicious pages.",
    "Malware can make devices slow, show unusual pop-ups, or make files unavailable. Avoid unknown downloads, unexpected attachments, and unusual links.",
    "Denial of Service can make a system slow or unavailable. Employees should report unavailable business systems instead of trying technical diagnosis.",
    "High-risk systems should be prioritized when they are business critical, internet-facing, connected to many systems, or running software with severe known vulnerabilities.",
    "Clear cyber guidance for normal employees should say what is affected, why it matters, what is unknown, and what simple action to take.",
]


def load_cwe_texts(limit=60):
    path = Path("cleaned_cwe.json")
    if not path.exists():
        return []

    cwes = json.load(open(path, encoding="utf-8"))
    priority = {
        "CWE-89", "CWE-79", "CWE-77", "CWE-22", "CWE-434", "CWE-400",
        "CWE-120", "CWE-119", "CWE-125", "CWE-352", "CWE-502", "CWE-94",
        "CWE-287", "CWE-306", "CWE-798",
    }
    selected = [c for c in cwes if c.get("cwe_id") in priority]
    selected.extend(cwes[: max(0, limit - len(selected))])

    return [
        f"{c['cwe_id']} {c['name']}: {c.get('description', '')}"
        for c in selected[:limit]
    ]


def load_attack_texts(limit=40):
    path = Path("final_technique_data.json")
    if not path.exists():
        path = Path("technique_with_tactics.json")
    if not path.exists():
        return []

    techniques = json.load(open(path, encoding="utf-8"))
    texts = []
    for tech in techniques[:limit]:
        tactics = ", ".join(tech.get("tactics", [])) or "unknown tactic"
        mitigations = ", ".join(tech.get("mitigations", [])[:3]) if tech.get("mitigations") else "no mitigation listed"
        texts.append(
            f"MITRE technique {tech.get('technique_id')} {tech.get('name')}: tactics {tactics}; mitigations {mitigations}."
        )
    return texts


texts = SAFE_GUIDANCE + load_cwe_texts() + load_attack_texts()

build_vector_db(texts)

from neo4j import GraphDatabase
from collections import defaultdict
import os

URI = os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687")
USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD", "12345678")

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))


def get_asset_data(tx):
    query = """
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (cw)-[:EXPLOITED_BY]->(t:ATTACK)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    CALL (a) {
        OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
        RETURN count(DISTINCT neighbor) AS connected_systems
    }

    RETURN a.id AS asset,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           c.id AS cve,
           c.cvss AS score,
           c.severity AS severity,
           r.confidence AS confidence,
           collect(DISTINCT cw.id) AS cwes,
           collect(DISTINCT t.name) AS attacks,
           connected_systems
    """
    return list(tx.run(query))


def compute_asset_risk(records):
    asset_map = defaultdict(lambda: {
        "hostname": "",
        "department": "Unknown",
        "criticality": "MEDIUM",
        "subnet": "APP",
        "weighted_sum": 0,
        "cve_set": set(),
        "cwe_set": set(),
        "attack_set": set(),
        "connected_systems": 0,
    })

    severity_weights = {
        "CRITICAL": 5,
        "HIGH": 3,
        "MEDIUM": 1,
        "LOW": 0.25,
    }
    confidence_weights = {
        "high": 1.5,
        "medium": 1.0,
        "low": 0.5,
    }
    criticality_weights = {
        "CRITICAL": 1.5,
        "HIGH": 1.25,
        "MEDIUM": 1.0,
        "LOW": 0.8,
    }
    subnet_weights = {
        "DMZ": 30,
        "DB": 20,
        "APP": 10,
    }

    for r in records:
        asset = r["asset"]
        data = asset_map[asset]
        data["hostname"] = r["hostname"] or asset
        data["department"] = r["department"] or "Unknown"
        data["criticality"] = r["criticality"] or "MEDIUM"
        data["subnet"] = r["subnet"] or "APP"
        data["connected_systems"] = max(data["connected_systems"], r["connected_systems"] or 0)
        data["cve_set"].add(r["cve"])
        for cwe in r["cwes"]:
            if cwe:
                data["cwe_set"].add(cwe)
        data["weighted_sum"] += (
            severity_weights.get(r["severity"], 0.5)
            * confidence_weights.get(r["confidence"], 0.5)
        )

        for attack in r["attacks"]:
            if attack:
                data["attack_set"].add(attack)

    final_scores = {}

    for asset, data in asset_map.items():
        base_score = (
            data["weighted_sum"] +
            len(data["cwe_set"]) * 0.8 +
            len(data["attack_set"]) * 0.5 +
            data["connected_systems"] * 2 +
            subnet_weights.get(data["subnet"], 10)
        )
        risk_score = base_score * criticality_weights.get(data["criticality"], 1.0)

        final_scores[asset] = {
            "score": risk_score,
            "hostname": data["hostname"],
            "department": data["department"],
            "criticality": data["criticality"],
            "subnet": data["subnet"],
            "cve_count": len(data["cve_set"]),
            "cwe_count": len(data["cwe_set"]),
            "attack_count": len(data["attack_set"]),
            "connected_systems": data["connected_systems"],
        }

    return final_scores


def analyze():
    with driver.session() as session:
        records = session.execute_read(get_asset_data)

    risk_scores = compute_asset_risk(records)
    return sorted(risk_scores.items(), key=lambda x: x[1]["score"], reverse=True)


if __name__ == "__main__":
    print("\nRunning weighted risk analysis...\n")
    ranked = analyze()
    print("===== TOP RISK ASSETS =====\n")

    for asset, data in ranked[:10]:
        print(f"""
Asset: {asset} ({data['hostname']})
Department: {data['department']}
Subnet: {data['subnet']}
Business Criticality: {data['criticality']}
Risk Score: {data['score']:.2f}
Known CVEs: {data['cve_count']}
Weakness Types: {data['cwe_count']}
Possible Attack Methods: {data['attack_count']}
Connected Systems: {data['connected_systems']}
Employee Meaning: this system should be prioritized for normal patching and IT review.
----------------------------
""")

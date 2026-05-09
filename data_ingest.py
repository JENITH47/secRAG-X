from neo4j import GraphDatabase
import json
import os
import re
from pathlib import Path

URI = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD", "12345678")

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))


SOFTWARE_ALIAS = {
    "nodejs": "node",
    "node.js": "node",
    "windowsserver": "windows",
    "windows server": "windows",
    "microsoftsqlserver": "sql",
    "microsoft sql server": "sql",
    "apache": "apache",
}


def normalize(name):
    if not name:
        return "unknown"
    cleaned = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    return SOFTWARE_ALIAS.get(cleaned, cleaned)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


assets = load_json("enterprise_assets.json")
cves = load_json("cleaned_cve.json")
mitre = load_json("final_technique_data.json") if Path("final_technique_data.json").exists() else load_json("technique_with_tactics.json")
cwes = load_json("cleaned_cwe.json")
network_data = load_json("network_sbom.json") if Path("network_sbom.json").exists() else None


def create_constraints(tx):
    tx.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE")
    tx.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:Software) REQUIRE s.normalized IS UNIQUE")
    tx.run("CREATE CONSTRAINT IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE")
    tx.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:ATTACK) REQUIRE t.id IS UNIQUE")
    tx.run("CREATE CONSTRAINT IF NOT EXISTS FOR (cw:CWE) REQUIRE cw.id IS UNIQUE")
    tx.run("CREATE CONSTRAINT IF NOT EXISTS FOR (sn:Subnet) REQUIRE sn.id IS UNIQUE")
    tx.run("CREATE CONSTRAINT IF NOT EXISTS FOR (co:Component) REQUIRE co.name IS UNIQUE")
    tx.run("CREATE INDEX IF NOT EXISTS FOR (c:CVE) ON (c.cvss)")
    tx.run("CREATE INDEX IF NOT EXISTS FOR (c:CVE) ON (c.severity)")


def insert_cwe(tx, cwe):
    tx.run(
        """
        MERGE (cw:CWE {id:$id})
        SET cw.name=$name,
            cw.description=$desc
        """,
        id=cwe["cwe_id"],
        name=cwe["name"],
        desc=cwe["description"],
    )


def cpe_products(cve):
    return sorted(
        {
            normalize(cpe.get("product", ""))
            for cpe in cve.get("cpe", [])
            if cpe.get("product")
        }
    )


def cpe_versions(cve):
    return sorted(
        {
            str(cpe.get("version", ""))
            for cpe in cve.get("cpe", [])
            if cpe.get("version")
        }
    )


def insert_cves(tx, cve):
    tx.run(
        """
        MERGE (c:CVE {id:$id})
        SET c.description=$desc,
            c.severity=$sev,
            c.cvss=$cvss,
            c.attack_type=$attack,
            c.published=$published,
            c.attack_vector=$attack_vector,
            c.privileges_required=$privileges_required,
            c.user_interaction=$user_interaction,
            c.cpe_products=$products,
            c.cpe_versions=$versions,
            c.cwe_ids=$cwe_ids
        """,
        id=cve["cve_id"],
        desc=cve.get("description", ""),
        sev=cve.get("severity", "UNKNOWN"),
        cvss=cve.get("cvss_score", 0),
        attack=cve.get("attack_type", ""),
        published=cve.get("published", ""),
        attack_vector=cve.get("attack_vector", "UNKNOWN"),
        privileges_required=cve.get("privileges_required", "UNKNOWN"),
        user_interaction=cve.get("user_interaction", "UNKNOWN"),
        products=cpe_products(cve),
        versions=cpe_versions(cve),
        cwe_ids=cve.get("cwe", []),
    )


def insert_mitre(tx, tech):
    tx.run(
        """
        MERGE (t:ATTACK {id:$id})
        SET t.name=$name,
            t.tactics=$tactics,
            t.mitigations=$mitigations
        """,
        id=tech["technique_id"],
        name=tech["name"],
        tactics=tech.get("tactics", []),
        mitigations=tech.get("mitigations", []),
    )


def insert_assets(tx, asset):
    tx.run(
        """
        MERGE (a:Asset {id:$id})
        SET a.hostname=$hostname,
            a.ip=$ip,
            a.os=$os,
            a.department=$department,
            a.criticality=$criticality
        """,
        id=asset["asset_id"],
        hostname=asset.get("hostname", ""),
        ip=asset.get("ip", ""),
        os=asset.get("os", ""),
        department=asset.get("department", "Unknown"),
        criticality=asset.get("criticality", "MEDIUM"),
    )

    for sw in asset.get("software", []):
        raw = sw.get("name")
        norm = normalize(raw)

        tx.run(
            """
            MERGE (s:Software {normalized:$norm})
            SET s.raw=$raw
            """,
            norm=norm,
            raw=raw,
        )

        tx.run(
            """
            MATCH (a:Asset {id:$aid}), (s:Software {normalized:$norm})
            MERGE (a)-[r:RUNS]->(s)
            SET r.version=$version
            """,
            aid=asset["asset_id"],
            norm=norm,
            version=sw.get("version", "unknown"),
        )


def match_keyword(text, keyword):
    return re.search(r"\b" + re.escape(keyword) + r"\b", text)


def link_cve_cwe(tx, cve):
    for cwe_id in cve.get("cwe", []):
        tx.run(
            """
            MATCH (c:CVE {id:$cid})
            MATCH (cw:CWE {id:$cwe})
            MERGE (c)-[:HAS_WEAKNESS {source:'nvd'}]->(cw)
            """,
            cid=cve["cve_id"],
            cwe=cwe_id,
        )

    text = (cve.get("description", "") + " " + cve.get("attack_type", "")).lower()
    mapping = [
        ("sql injection", "CWE-89"),
        ("command injection", "CWE-77"),
        ("xss", "CWE-79"),
        ("csrf", "CWE-352"),
        ("path traversal", "CWE-22"),
        ("file upload", "CWE-434"),
        ("deserialization", "CWE-502"),
        ("race condition", "CWE-362"),
        ("out-of-bounds", "CWE-125"),
        ("buffer overflow", "CWE-120"),
        ("memory corruption", "CWE-119"),
        ("denial of service", "CWE-400"),
    ]

    for key, cwe_id in mapping:
        if match_keyword(text, key):
            tx.run(
                """
                MATCH (c:CVE {id:$cid})
                MATCH (cw:CWE {id:$cwe})
                MERGE (c)-[:HAS_WEAKNESS {source:'keyword'}]->(cw)
                """,
                cid=cve["cve_id"],
                cwe=cwe_id,
            )


def link_top_cves_per_software(tx):
    software_matches = {
        "apache": {"exact": ["apache", "httpd", "httpserver", "apachehttpserver"], "prefix": []},
        "windows": {"exact": ["windows"], "prefix": ["windowsserver", "windows10", "windows11"]},
        "node": {"exact": ["node", "nodejs", "node.js"], "prefix": ["nodejs"]},
        "sql": {"exact": ["microsoftsqlserver", "sqlserver"], "prefix": ["microsoftsqlserver", "sqlserver"]},
        "mongodb": {"exact": ["mongodb"], "prefix": []},
        "mysql": {"exact": ["mysql"], "prefix": []},
        "nginx": {"exact": ["nginx"], "prefix": []},
        "ubuntu": {"exact": ["ubuntu"], "prefix": []},
        "wireshark": {"exact": ["wireshark"], "prefix": []},
        "php": {"exact": ["php"], "prefix": []},
        "openssl": {"exact": ["openssl"], "prefix": []},
        "python": {"exact": ["python"], "prefix": []},
        "docker": {"exact": ["docker"], "prefix": []},
        "nmap": {"exact": ["nmap"], "prefix": []},
    }

    for sw, match in software_matches.items():
        norm = normalize(sw)
        exact = [normalize(alias) for alias in match["exact"]]
        prefixes = [normalize(alias) for alias in match["prefix"]]

        tx.run(
            """
            MATCH (s:Software {normalized:$name})
            MATCH (c:CVE)
            WHERE c.cvss >= 7
              AND (
                any(product IN c.cpe_products WHERE product IN $exact)
                OR any(product IN c.cpe_products WHERE any(prefix IN $prefixes WHERE product STARTS WITH prefix))
              )
            WITH s, c
            ORDER BY c.cvss DESC
            LIMIT 300
            MERGE (s)-[r:HAS_VULN {source:'cpe'}]->(c)
            SET r.confidence='medium',
                r.match_level='product'
            """,
            name=norm,
            exact=exact,
            prefixes=prefixes,
        )


def link_asset_cves_version_aware(tx):
    # Asset-specific links preserve software version evidence. These are better
    # for reasoning than global Software->CVE links because each RUNS edge has
    # its own version.
    tx.run(
        """
        MATCH (a:Asset)-[runs:RUNS]->(s:Software)
        MATCH (c:CVE)
        WHERE c.cvss >= 7
          AND (
            (s.normalized = 'windows' AND (
                (runs.version = '10' AND any(product IN c.cpe_products WHERE product STARTS WITH 'windows10'))
                OR (runs.version = '2016' AND any(product IN c.cpe_products WHERE product STARTS WITH 'windowsserver2016'))
                OR (runs.version = '2019' AND any(product IN c.cpe_products WHERE product STARTS WITH 'windowsserver2019'))
            ))
            OR (s.normalized = 'sql' AND (
                any(product IN c.cpe_products WHERE product IN ['microsoftsqlserver', 'sqlserver'])
                OR any(product IN c.cpe_products WHERE product STARTS WITH ('microsoftsqlserver' + runs.version))
                OR any(product IN c.cpe_products WHERE product STARTS WITH ('sqlserver' + runs.version))
            ))
            OR (s.normalized = 'apache' AND any(product IN c.cpe_products WHERE product IN ['apache', 'httpd', 'httpserver', 'apachehttpserver']))
            OR (s.normalized = 'node' AND any(product IN c.cpe_products WHERE product IN ['node', 'nodejs', 'node.js'] OR product STARTS WITH 'nodejs'))
            OR (s.normalized IN ['ubuntu', 'php', 'mysql', 'nginx', 'wireshark', 'openssl', 'mongodb', 'docker', 'python', 'nmap'] AND any(product IN c.cpe_products WHERE product = s.normalized))
          )
        WITH a, runs, s, c,
             CASE
                 WHEN s.normalized = 'windows' AND runs.version = '10' AND any(product IN c.cpe_products WHERE product STARTS WITH 'windows10') THEN 'version'
                 WHEN s.normalized = 'windows' AND runs.version = '2016' AND any(product IN c.cpe_products WHERE product STARTS WITH 'windowsserver2016') THEN 'version'
                 WHEN s.normalized = 'windows' AND runs.version = '2019' AND any(product IN c.cpe_products WHERE product STARTS WITH 'windowsserver2019') THEN 'version'
                 WHEN s.normalized = 'sql' AND any(product IN c.cpe_products WHERE product STARTS WITH ('microsoftsqlserver' + runs.version) OR product STARTS WITH ('sqlserver' + runs.version)) THEN 'version'
                 WHEN runs.version IN c.cpe_versions THEN 'version'
                 WHEN 'all' IN c.cpe_versions THEN 'product'
                 WHEN 'unspecified' IN c.cpe_versions THEN 'product'
                 ELSE 'product'
             END AS match_level
        MERGE (a)-[r:AFFECTED_BY {software:s.normalized, cve:c.id}]->(c)
        SET r.version=runs.version,
            r.software_raw=CASE
                WHEN s.normalized = 'windows' AND runs.version = '10' THEN 'windows'
                WHEN s.normalized = 'windows' THEN 'windows server'
                ELSE s.raw
            END,
            r.source='cpe',
            r.match_level=match_level,
            r.confidence=CASE match_level
                WHEN 'version' THEN 'high'
                ELSE 'medium'
            END
        """
    )


def link_cwe_attack(tx):
    mapping = {
        "CWE-89": "Command and Scripting Interpreter",
        "CWE-77": "Command and Scripting Interpreter",
        "CWE-79": "Exploitation for Client Execution",
        "CWE-120": "Memory Corruption",
        "CWE-119": "Memory Corruption",
        "CWE-125": "Memory Corruption",
        "CWE-400": "Endpoint Denial of Service",
        "CWE-22": "Path Traversal",
        "CWE-434": "Ingress Tool Transfer",
        "CWE-352": "Phishing",
        "CWE-502": "Exploitation for Client Execution",
    }

    for cwe, attack in mapping.items():
        tx.run(
            """
            MATCH (cw:CWE {id:$cwe})
            MATCH (t:ATTACK {name:$attack})
            MERGE (cw)-[:EXPLOITED_BY]->(t)
            """,
            cwe=cwe,
            attack=attack,
        )


def insert_network_context(tx, data):
    if not data:
        return

    for subnet in data.get("subnets", []):
        tx.run(
            """
            MERGE (sn:Subnet {id:$id})
            SET sn.cidr=$cidr,
                sn.type=$type
            """,
            id=subnet.get("subnet_id"),
            cidr=subnet.get("cidr", ""),
            type=subnet.get("type", "unknown"),
        )

    for item in data.get("assets", []):
        tx.run(
            """
            MATCH (a:Asset {id:$asset_id})
            MERGE (sn:Subnet {id:$subnet})
            MERGE (a)-[:IN_SUBNET]->(sn)
            """,
            asset_id=item.get("asset_id"),
            subnet=item.get("subnet", "UNKNOWN"),
        )

        for component in item.get("sbom", []):
            tx.run(
                """
                MATCH (a:Asset {id:$asset_id})
                MERGE (co:Component {name:$name})
                SET co.version=$version
                MERGE (a)-[:HAS_COMPONENT]->(co)
                """,
                asset_id=item.get("asset_id"),
                name=normalize(component.get("component", "")),
                version=component.get("version", "unknown"),
            )

    for connection in data.get("connections", []):
        tx.run(
            """
            MATCH (src:Asset {id:$source})
            MATCH (dst:Asset {id:$target})
            MERGE (src)-[r:CONNECTED_TO]->(dst)
            SET r.protocol=$protocol
            """,
            source=connection.get("source"),
            target=connection.get("target"),
            protocol=connection.get("protocol", "unknown"),
        )


with driver.session() as session:
    print("Resetting database...")
    session.run("MATCH (n) DETACH DELETE n")

    print("Creating constraints...")
    session.execute_write(create_constraints)

    print("Inserting CWE...")
    for c in cwes:
        session.execute_write(insert_cwe, c)

    print("Inserting CVEs...")
    for c in cves:
        session.execute_write(insert_cves, c)

    print("Inserting ATTACK...")
    for m in mitre:
        session.execute_write(insert_mitre, m)

    print("Inserting Assets...")
    for a in assets:
        session.execute_write(insert_assets, a)

    print("Skipping global Software to CVE links; asset-specific AFFECTED_BY links are used for reasoning.")

    print("Linking Assets to CVE with version-aware confidence...")
    session.execute_write(link_asset_cves_version_aware)

    print("Linking CVE to CWE...")
    for c in cves:
        session.execute_write(link_cve_cwe, c)

    print("Linking CWE to ATTACK...")
    session.execute_write(link_cwe_attack)

    print("Adding network and SBOM context...")
    session.execute_write(insert_network_context, network_data)


print("GRAPH BUILT SUCCESSFULLY")

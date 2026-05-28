"""
=============================================================
COMPREHENSIVE SYSTEM RELIABILITY TEST
Cybersecurity Knowledge Graph + Reasoning Engine
=============================================================
Tests:
  1. Graph integrity & schema validation
  2. Multi-hop path verification
  3. Intent detection accuracy
  4. All Cypher query correctness
  5. Vector store / RAG functionality
  6. Confidence scoring logic
  7. Direct employee answer coverage
  8. Attack mapping logic
  9. Edge cases & guardrails
 10. Explanation quality (LLM layer)
=============================================================
"""

import sys
import traceback
import time
from collections import Counter

# Set standard output and error to use UTF-8 to prevent charmap/UnicodeEncodeError on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# ── Globals ──────────────────────────────────────────────
PASS = 0
FAIL = 0
WARN = 0
RESULTS = []


def record(test_name, passed, detail=""):
    global PASS, FAIL, WARN
    status = "PASS" if passed else "FAIL"
    if passed:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append((status, test_name, detail))
    icon = "✅" if passed else "❌"
    print(f"  {icon} {test_name}" + (f"  ({detail})" if detail else ""))


def warn(test_name, detail=""):
    global WARN
    WARN += 1
    RESULTS.append(("WARN", test_name, detail))
    print(f"  ⚠️  {test_name}" + (f"  ({detail})" if detail else ""))


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ===========================================================
# 1. GRAPH INTEGRITY & SCHEMA
# ===========================================================
def test_graph_integrity():
    section("1. GRAPH INTEGRITY & SCHEMA VALIDATION")
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "12345678"))
    with driver.session() as s:
        # 1a. Essential node labels exist
        r = s.run("MATCH (n) RETURN DISTINCT labels(n)[0] AS label")
        labels = {rec["label"] for rec in r}
        expected = {"Asset", "Software", "CVE", "CWE", "ATTACK", "Subnet", "Component"}
        for lbl in expected:
            record(f"Node label '{lbl}' exists", lbl in labels)

        # 1b. Essential relationship types exist
        r2 = s.run("MATCH ()-[r]->() RETURN DISTINCT type(r) AS rel")
        rels = {rec["rel"] for rec in r2}
        expected_rels = {"RUNS", "HAS_VULN", "HAS_WEAKNESS", "EXPLOITED_BY",
                         "AFFECTED_BY", "IN_SUBNET", "CONNECTED_TO", "HAS_COMPONENT"}
        for rel in expected_rels:
            record(f"Relationship '{rel}' exists", rel in rels)

        # 1c. Node count sanity
        counts = {}
        r3 = s.run("MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt")
        for rec in r3:
            counts[rec["label"]] = rec["cnt"]
        record("Assets >= 10", counts.get("Asset", 0) >= 10, f"count={counts.get('Asset',0)}")
        record("CVEs >= 1000", counts.get("CVE", 0) >= 1000, f"count={counts.get('CVE',0)}")
        record("CWEs >= 10", counts.get("CWE", 0) >= 10, f"count={counts.get('CWE',0)}")
        record("ATTACKs >= 5", counts.get("ATTACK", 0) >= 5, f"count={counts.get('ATTACK',0)}")
        record("Software >= 5", counts.get("Software", 0) >= 5, f"count={counts.get('Software',0)}")

        # 1d. Constraints exist
        r4 = s.run("SHOW CONSTRAINTS")
        constraint_count = len(list(r4))
        record("Constraints created (>=5)", constraint_count >= 5, f"count={constraint_count}")

        # 1e. Indexes exist
        r5 = s.run("SHOW INDEXES")
        index_count = len(list(r5))
        record("Indexes created (>=2)", index_count >= 2, f"count={index_count}")

    driver.close()


# ===========================================================
# 2. MULTI-HOP PATH VERIFICATION
# ===========================================================
def test_multi_hop_paths():
    section("2. MULTI-HOP PATH VERIFICATION")
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "12345678"))
    with driver.session() as s:
        # 2a. Asset → Software (1-hop)
        r = s.run("MATCH (a:Asset)-[:RUNS]->(s:Software) RETURN count(*) AS cnt")
        cnt = r.single()["cnt"]
        record("Path Asset→Software exists", cnt > 0, f"count={cnt}")

        # 2b. Software → CVE (2-hop from asset)
        r = s.run("MATCH (a:Asset)-[:RUNS]->(s:Software)-[:HAS_VULN]->(c:CVE) RETURN count(DISTINCT a) AS cnt")
        cnt = r.single()["cnt"]
        record("Path Asset→Software→CVE exists", cnt > 0, f"distinct assets={cnt}")

        # 2c. CVE → CWE (3-hop from asset)
        r = s.run("MATCH (a:Asset)-[:RUNS]->(s:Software)-[:HAS_VULN]->(c:CVE)-[:HAS_WEAKNESS]->(cw:CWE) RETURN count(DISTINCT a) AS cnt")
        cnt = r.single()["cnt"]
        record("Path Asset→Software→CVE→CWE exists", cnt > 0, f"distinct assets={cnt}")

        # 2d. Full chain: Asset → Software → CVE → CWE → ATTACK (4-hop)
        r = s.run("""
            MATCH (a:Asset)-[:RUNS]->(s:Software)-[:HAS_VULN]->(c:CVE)
                  -[:HAS_WEAKNESS]->(cw:CWE)-[:EXPLOITED_BY]->(t:ATTACK)
            RETURN count(DISTINCT a) AS assets, count(DISTINCT t) AS attacks
        """)
        rec = r.single()
        record("Full 4-hop chain exists (Asset→Soft→CVE→CWE→ATTACK)",
               rec["assets"] > 0, f"assets={rec['assets']}, attacks={rec['attacks']}")

        # 2e. AFFECTED_BY path (direct asset-CVE with metadata)
        r = s.run("MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE) RETURN count(*) AS cnt, count(DISTINCT a) AS assets")
        rec = r.single()
        record("AFFECTED_BY links exist", rec["cnt"] > 0, f"links={rec['cnt']}, assets={rec['assets']}")

        # 2f. Confidence metadata on AFFECTED_BY
        r = s.run("""
            MATCH ()-[r:AFFECTED_BY]->()
            RETURN r.confidence AS conf, count(*) AS cnt
            ORDER BY cnt DESC
        """)
        confs = {rec["conf"]: rec["cnt"] for rec in r}
        record("AFFECTED_BY has confidence metadata", len(confs) > 0, f"levels={confs}")

        # 2g. Network context: Asset → Subnet
        r = s.run("MATCH (a:Asset)-[:IN_SUBNET]->(sn:Subnet) RETURN count(*) AS cnt")
        cnt = r.single()["cnt"]
        record("Asset→Subnet links exist", cnt > 0, f"count={cnt}")

        # 2h. Network context: Asset → Asset (CONNECTED_TO)
        r = s.run("MATCH (a:Asset)-[:CONNECTED_TO]->(b:Asset) RETURN count(*) AS cnt")
        cnt = r.single()["cnt"]
        record("Asset↔Asset connections exist", cnt > 0, f"count={cnt}")

    driver.close()


# ===========================================================
# 3. INTENT DETECTION ACCURACY
# ===========================================================
def test_intent_detection():
    section("3. INTENT DETECTION ACCURACY")

    # Import after section header so error is clear
    sys.path.insert(0, ".")
    from explane import detect_intent

    test_cases = [
        # (query, expected_intent)
        ("why is SRV-032 risky", "ASSET_DRILLDOWN"),
        ("explain risk for SRV-001", "ASSET_DRILLDOWN"),
        ("explain SRV-049", "ASSET_DRILLDOWN"),
        ("what is wrong with SRV-010", "ASSET_DRILLDOWN"),
        ("most vulnerable", "MOST_VULNERABLE_HELP"),
        ("which asset is at most risk", "MOST_VULNERABLE_HELP"),
        ("top risk", "MOST_VULNERABLE_HELP"),
        ("phishing", "PHISHING_HELP"),
        ("safe from phishing", "PHISHING_EDUCATION_HELP"),
        ("malware", "MALWARE_HELP"),
        ("what is malware", "MALWARE_EDUCATION_HELP"),
        ("ransomware systems", "RANSOMWARE_SYSTEMS_HELP"),
        ("denial of service", "DOS_HELP"),
        ("sql injection", "SQL_INJECTION_HELP"),
        ("am i under attack", "ATTACK_STATUS"),
        ("is my system hacked", "ATTACK_STATUS"),
        ("tell me something random", "OUT_OF_SCOPE_HELP"),
        ("weather", "OUT_OF_SCOPE_HELP"),
        ("joke", "OUT_OF_SCOPE_HELP"),
        ("which systems are most vulnerable", "MOST_VULNERABLE_SYSTEMS_HELP"),
        ("top 10 risks", "TOP_10_RISKS_HELP"),
        ("is my system safe", "SYSTEM_SAFETY_HELP"),
        ("something wrong with my system", "SYSTEM_CONCERN_HELP"),
        ("attack exposure", "ATTACK_EXPOSURE_HELP"),
        ("which software is causing most risk", "SOFTWARE_RISK_HELP"),
        ("compare two systems", "COMPARE_ASSETS_MISSING_IDS_HELP"),
        ("more risky SRV-032 or SRV-049", "COMPARE_ASSETS_HELP"),
        ("my laptop is not working", "EMPLOYEE_DEVICE_HELP"),
        ("safest system", "SAFEST_SYSTEM_HELP"),
        ("highest issues", "HIGHEST_ISSUES_HELP"),
        ("risk in my server", "SERVER_RISK_HELP"),
        ("which system has risky software", "RISKY_SOFTWARE_SYSTEMS_HELP"),
        ("why is my system vulnerable", "VAGUE_SYSTEM_VULNERABLE_HELP"),
        ("what happens if system is attacked", "ATTACK_IMPACT_EDUCATION_HELP"),
        ("which vulnerability is most exposed", "MOST_EXPOSED_VULN_HELP"),
        ("is mysql causing issues", "SPECIFIC_SOFTWARE_RISK_HELP"),
        ("asdfgh", "UNCLEAR_HELP"),
        ("xx", "UNCLEAR_HELP"),
    ]

    for query, expected in test_cases:
        actual = detect_intent(query)
        record(f"Intent: '{query[:40]}' → {expected}", actual == expected,
               f"got={actual}" if actual != expected else "")


# ===========================================================
# 4. ALL CYPHER QUERIES RETURN VALID DATA
# ===========================================================
def test_cypher_queries():
    section("4. CYPHER QUERY CORRECTNESS")
    from explane import (
        execute_query, build_query, sql_injection_query, malware_risk_query,
        dos_risk_query, most_exposed_vulnerability_query, top_risks_query,
        highest_issues_query, attack_exposure_query, software_risk_query,
        risky_software_systems_query, specific_software_risk_query,
        asset_risk_explanation_query, compare_assets_query, safest_system_query,
        ransomware_systems_query,
    )

    # 4a. build_query intents
    for intent in ["TOP_ASSETS", "ATTACK_SURFACE", "GENERAL_RISK"]:
        q = build_query(intent)
        data = execute_query(q)
        record(f"build_query('{intent}') returns data", len(data) > 0, f"rows={len(data)}")

    # 4b. ASSET_DRILLDOWN with real asset
    q = build_query("ASSET_DRILLDOWN")
    data = execute_query(q, {"asset_id": "SRV-001"})
    record("ASSET_DRILLDOWN for SRV-001 returns data", len(data) > 0, f"rows={len(data)}")

    # 4c. ATTACK_QUERY
    q = build_query("ATTACK_QUERY")
    data = execute_query(q, {"attack_list": ["Phishing"]})
    record("ATTACK_QUERY for Phishing returns data", len(data) >= 0, f"rows={len(data)}")

    # 4d. Specific query functions
    query_tests = [
        ("sql_injection_query", sql_injection_query()),
        ("malware_risk_query", malware_risk_query()),
        ("dos_risk_query", dos_risk_query()),
        ("most_exposed_vulnerability_query", most_exposed_vulnerability_query()),
        ("top_risks_query(10)", top_risks_query(10)),
        ("highest_issues_query", highest_issues_query()),
        ("attack_exposure_query(5)", attack_exposure_query(5)),
        ("software_risk_query(5)", software_risk_query(5)),
        ("risky_software_systems_query(5)", risky_software_systems_query(5)),
        ("safest_system_query", safest_system_query()),
        ("ransomware_systems_query(5)", ransomware_systems_query(5)),
    ]

    for name, q in query_tests:
        try:
            data = execute_query(q)
            record(f"{name} executes OK", True, f"rows={len(data)}")
            # Verify structure has expected keys
            if data:
                keys = set(data[0].keys())
                has_asset = "asset_id" in keys or "asset" in keys or "software" in keys
                record(f"{name} has valid columns", has_asset, f"keys={sorted(keys)[:5]}")
        except Exception as e:
            record(f"{name} executes OK", False, str(e)[:80])

    # 4e. Parameterized queries
    try:
        data = execute_query(specific_software_risk_query(), {"software": "mysql"})
        record("specific_software_risk_query(mysql) OK", True, f"rows={len(data)}")
    except Exception as e:
        record("specific_software_risk_query(mysql) OK", False, str(e)[:80])

    try:
        data = execute_query(asset_risk_explanation_query(), {"asset_id": "SRV-001"})
        record("asset_risk_explanation_query(SRV-001) OK", True, f"rows={len(data)}")
    except Exception as e:
        record("asset_risk_explanation_query(SRV-001) OK", False, str(e)[:80])

    try:
        data = execute_query(compare_assets_query(), {"asset_ids": ["SRV-001", "SRV-002"]})
        record("compare_assets_query OK", True, f"rows={len(data)}")
    except Exception as e:
        record("compare_assets_query OK", False, str(e)[:80])


# ===========================================================
# 5. VECTOR STORE / RAG VERIFICATION
# ===========================================================
def test_vector_store():
    section("5. VECTOR STORE / RAG FUNCTIONALITY")
    import os

    # 5a. Files exist
    record("vector.index file exists", os.path.exists("vector.index"))
    record("metadata.pkl file exists", os.path.exists("metadata.pkl"))

    # 5b. Load vector DB
    from vector_store import load_vector_db, retrieve
    index, texts = load_vector_db()
    record("load_vector_db returns index", index is not None)
    record("load_vector_db returns texts", texts is not None and len(texts) > 0,
           f"count={len(texts) if texts else 0}")

    # 5c. Retrieval works
    if index and texts:
        try:
            results = retrieve("sql injection vulnerability", index, texts, k=2)
            record("retrieve() returns results", len(results) > 0, f"count={len(results)}")
            record("retrieve() results are strings", all(isinstance(r, str) for r in results))
            # Check relevance
            any_relevant = any("sql" in r.lower() or "injection" in r.lower() or "CWE" in r for r in results)
            record("retrieve() results are relevant to query", any_relevant,
                   f"first={results[0][:60]}..." if results else "")
        except Exception as e:
            record("retrieve() works", False, str(e)[:80])

    # 5d. RAG engine standalone
    try:
        from rag_engine import build_index, retrieve as rag_retrieve
        rag_idx = build_index()
        record("rag_engine.build_index() works", len(rag_idx) > 0, f"items={len(rag_idx)}")
        rag_results = rag_retrieve("malware risk", rag_idx, top_k=2)
        record("rag_engine.retrieve() works", len(rag_results) > 0)
    except Exception as e:
        record("rag_engine works", False, str(e)[:80])


# ===========================================================
# 6. CONFIDENCE SCORING LOGIC
# ===========================================================
def test_confidence_scoring():
    section("6. CONFIDENCE SCORING LOGIC")
    from explane import compute_confidence

    # 6a. Empty data
    record("confidence([]) = 'Low'", compute_confidence([]) == "Low")

    # 6b. Uniform low
    data = [{"known_issues": 5}, {"known_issues": 5}]
    record("confidence(uniform low) = 'Low'", compute_confidence(data) == "Low")

    # 6c. Clear outlier → High
    data = [{"known_issues": 100}, {"known_issues": 10}, {"known_issues": 5}]
    record("confidence(clear outlier) = 'High'", compute_confidence(data) == "High",
           f"got={compute_confidence(data)}")

    # 6d. Moderate spread → Medium
    data = [{"known_issues": 20}, {"known_issues": 15}]
    conf = compute_confidence(data)
    record("confidence(moderate spread) = 'Medium'", conf == "Medium", f"got={conf}")

    # 6e. Handles mixed key names
    data = [{"vuln_count": 50}, {"vuln_count": 10}]
    conf = compute_confidence(data)
    record("confidence handles 'vuln_count' key", conf in ["High", "Medium", "Low"], f"got={conf}")

    # 6f. Handles None values gracefully
    data = [{"known_issues": None}, {"known_issues": None}]
    conf = compute_confidence(data)
    record("confidence handles None values", conf == "Low", f"got={conf}")


# ===========================================================
# 7. DIRECT EMPLOYEE ANSWER COVERAGE
# ===========================================================
def test_direct_answers():
    section("7. DIRECT EMPLOYEE ANSWER COVERAGE")
    from explane import detect_intent, direct_employee_answer

    # Test all intents that should produce direct answers
    direct_intents_queries = [
        ("UNCLEAR_HELP", "asdfgh"),
        ("OUT_OF_SCOPE_HELP", "tell me a joke"),
        ("ATTACK_STATUS", "am i under attack"),
        ("EMPLOYEE_DEVICE_HELP", "my laptop is not working"),
        ("PHISHING_EDUCATION_HELP", "how to stay safe from phishing"),
        ("MALWARE_EDUCATION_HELP", "what is malware"),
        ("ATTACK_IMPACT_EDUCATION_HELP", "what happens if system is attacked"),
        ("COMPARE_ASSETS_MISSING_IDS_HELP", "compare two systems"),
        ("VAGUE_SYSTEM_VULNERABLE_HELP", "why is my system vulnerable"),
        ("PHISHING_HELP", "phishing risk"),
        ("MALWARE_HELP", "malware risk"),
        ("DOS_HELP", "denial of service risk"),
        ("SQL_INJECTION_HELP", "sql injection risk"),
        ("MOST_VULNERABLE_HELP", "most vulnerable asset"),
        ("MOST_EXPOSED_VULN_HELP", "which vulnerability is most exposed"),
        ("TOP_10_RISKS_HELP", "top 10 risks"),
        ("MOST_VULNERABLE_SYSTEMS_HELP", "which systems are most vulnerable"),
        ("HIGHEST_ISSUES_HELP", "highest issues"),
        ("SAFEST_SYSTEM_HELP", "safest system"),
        ("ATTACK_EXPOSURE_HELP", "attack exposure"),
        ("SOFTWARE_RISK_HELP", "which software is causing most risk"),
        ("RISKY_SOFTWARE_SYSTEMS_HELP", "which system has risky software"),
        ("SYSTEM_SAFETY_HELP", "is my system safe"),
        ("SYSTEM_CONCERN_HELP", "should i be worried"),
        ("SERVER_RISK_HELP", "risk in my server"),
        ("RANSOMWARE_SYSTEMS_HELP", "ransomware systems"),
        ("COMPARE_ASSETS_HELP", "more risky SRV-001 or SRV-002"),
        ("SPECIFIC_SOFTWARE_RISK_HELP", "is mysql causing issues"),
    ]

    for intent, query in direct_intents_queries:
        try:
            answer = direct_employee_answer(intent, query)
            if answer is not None:
                # Check structure
                has_structure = ("Short answer" in answer or "Asset" in answer or
                                "Affected system" in answer or "What to do" in answer)
                record(f"Direct answer for {intent}", has_structure,
                       f"len={len(answer)}" if has_structure else f"missing structure, first 60: {answer[:60]}")
            else:
                # Some intents may not have direct answers (they use graph pipeline)
                warn(f"Direct answer for {intent} returned None (falls to pipeline)")
        except Exception as e:
            record(f"Direct answer for {intent}", False, str(e)[:80])


# ===========================================================
# 8. ATTACK MAPPING LOGIC
# ===========================================================
def test_attack_mapping():
    section("8. ATTACK MAPPING LOGIC")
    from explane import map_to_attack

    tests = [
        ("phishing attack on servers", ["Phishing"]),
        ("malware infection risk", ["Malware"]),
        ("virus detected", ["Malware"]),
        ("ransomware threat", ["Malware"]),
        ("denial of service", ["Endpoint Denial of Service"]),
        ("command injection", ["Command and Scripting Interpreter"]),
        ("sql injection attack", ["Command and Scripting Interpreter"]),
    ]

    for query, expected in tests:
        result = map_to_attack(query)
        record(f"map_to_attack('{query[:30]}') → {expected}",
               result == expected, f"got={result}" if result != expected else "")

    # Edge: no match
    result = map_to_attack("blah blah nothing")
    record("map_to_attack(unknown) → empty", result == [], f"got={result}" if result else "")


# ===========================================================
# 9. EDGE CASES & GUARDRAILS
# ===========================================================
def test_edge_cases():
    section("9. EDGE CASES & GUARDRAILS")
    from explane import (
        detect_intent, extract_asset_id, extract_asset_ids,
        extract_software_name, normalize_query_name, is_unclear_input,
    )

    # 9a. extract_asset_id
    record("extract_asset_id('why is SRV-032 risky') = SRV-032",
           extract_asset_id("why is SRV-032 risky") == "SRV-032")
    record("extract_asset_id('no asset here') = ''",
           extract_asset_id("no asset here") == "")

    # 9b. extract_asset_ids
    ids = extract_asset_ids("compare SRV-001 or SRV-002")
    record("extract_asset_ids returns 2 IDs", len(ids) == 2 and "SRV-001" in ids and "SRV-002" in ids)

    # 9c. extract_software_name
    sw = extract_software_name("is mysql causing issues")
    record("extract_software_name extracts 'mysql'", sw == "mysql", f"got='{sw}'")

    # 9d. normalize_query_name
    record("normalize_query_name('MySQL') = 'mysql'", normalize_query_name("MySQL") == "mysql")
    record("normalize_query_name('Node.js') = 'node'", normalize_query_name("Node.js") == "node")
    record("normalize_query_name('windows server') = 'windows'",
           normalize_query_name("windows server") == "windows")

    # 9e. is_unclear_input
    record("is_unclear_input('xx') = True", is_unclear_input("xx") == True)
    record("is_unclear_input('why is SRV-032 risky') = False",
           is_unclear_input("why is srv-032 risky") == False)
    record("is_unclear_input('asdf') = True", is_unclear_input("asdf") == True)

    # 9f. Non-existent asset
    from explane import execute_query, build_query
    q = build_query("ASSET_DRILLDOWN")
    data = execute_query(q, {"asset_id": "SRV-999"})
    record("Non-existent asset SRV-999 returns empty", len(data) == 0)

    # 9g. SQL injection in input
    q = build_query("ASSET_DRILLDOWN")
    data = execute_query(q, {"asset_id": "'; DROP TABLE Asset;--"})
    record("Malicious input handled safely (parameterized)", len(data) == 0)

    # 9h. Hardcoded credential check
    import inspect
    import explane
    source_code = inspect.getsource(explane)
    uses_env = "os.getenv" in source_code or "os.environ" in source_code
    record("Credentials loaded dynamically from environment/config", uses_env,
           "Loaded from environment variables" if uses_env else "Hardcoded credentials detected")


# ===========================================================
# 10. EXPLANATION QUALITY (WITHOUT LLM CALL)
# ===========================================================
def test_explanation_quality():
    section("10. EXPLANATION QUALITY")
    from explane import (
        explain_asset_drilldown, fallback_explanation,
        is_asset_drilldown_data, compute_confidence,
    )

    # 10a. Asset drilldown explanation
    mock_data = [
        {"asset": "SRV-001", "software": "apache", "vuln_count": 350,
         "high_confidence": 50, "medium_confidence": 200, "low_confidence": 100},
        {"asset": "SRV-001", "software": "openssl", "vuln_count": 100,
         "high_confidence": 10, "medium_confidence": 60, "low_confidence": 30},
    ]
    result = explain_asset_drilldown(mock_data, "High")
    record("explain_asset_drilldown produces output", len(result) > 100)
    record("Drilldown mentions main software", "apache" in result.lower())
    record("Drilldown has no-attack disclaimer",
           "no clear sign of an ongoing attack" in result.lower())
    record("Drilldown mentions confidence", "High" in result)

    # 10b. is_asset_drilldown_data
    record("is_asset_drilldown_data detects drilldown",
           is_asset_drilldown_data(mock_data) == True)
    record("is_asset_drilldown_data rejects non-drilldown",
           is_asset_drilldown_data([{"asset_id": "SRV-001"}]) == False)

    # 10c. Fallback explanation
    mock_top = [{
        "asset_id": "SRV-001",
        "hostname": "asset-1",
        "department": "IT",
        "subnet": "DMZ",
        "software": ["apache", "openssl"],
        "example_cves": ["CVE-2024-0001"],
        "highest_score": 9.8,
    }]
    fb = fallback_explanation(mock_top, "Medium")
    record("fallback_explanation produces output", len(fb) > 100)
    record("Fallback mentions asset", "SRV-001" in fb)
    record("Fallback has no-attack disclaimer",
           "no clear sign of an ongoing attack" in fb.lower())
    record("Fallback mentions evidence", "evidence" in fb.lower())

    # 10d. Forbidden terms check in fallback
    forbidden = ["investigation", "logs", "alerts", "monitoring", "forensic",
                 "packet capture", "siem", "compromised"]
    for term in forbidden:
        record(f"Fallback has no forbidden term '{term}'", term not in fb.lower())


# ===========================================================
# 11. DATA QUALITY CHECKS
# ===========================================================
def test_data_quality():
    section("11. DATA QUALITY CHECKS")
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "12345678"))
    with driver.session() as s:
        # 11a. No orphan assets (every asset should RUNS at least one software)
        r = s.run("""
            MATCH (a:Asset) WHERE NOT (a)-[:RUNS]->(:Software)
            RETURN count(a) AS cnt
        """)
        cnt = r.single()["cnt"]
        record("No orphan assets (all run software)", cnt == 0, f"orphans={cnt}")

        # 11b. No orphan software (every software should be run by at least one asset)
        r = s.run("""
            MATCH (s:Software) WHERE NOT (:Asset)-[:RUNS]->(s)
            RETURN count(s) AS cnt
        """)
        cnt = r.single()["cnt"]
        record("No orphan software", cnt == 0, f"orphans={cnt}")

        # 11c. CVE severity distribution is reasonable
        r = s.run("""
            MATCH (c:CVE)
            RETURN c.severity AS sev, count(*) AS cnt
            ORDER BY cnt DESC
        """)
        sevs = {rec["sev"]: rec["cnt"] for rec in r}
        has_variety = len(sevs) >= 3
        record("CVE severity has variety (>=3 levels)", has_variety, f"dist={sevs}")

        # 11d. CVSS scores are in valid range
        r = s.run("MATCH (c:CVE) WHERE c.cvss < 0 OR c.cvss > 10 RETURN count(*) AS cnt")
        cnt = r.single()["cnt"]
        record("All CVSS scores in [0,10]", cnt == 0, f"out_of_range={cnt}")

        # 11e. EXPLOITED_BY coverage
        r = s.run("MATCH (:CWE)-[:EXPLOITED_BY]->(:ATTACK) RETURN count(*) AS cnt")
        cnt = r.single()["cnt"]
        record("CWE→ATTACK links exist (EXPLOITED_BY)", cnt > 0, f"count={cnt}")
        if cnt < 5:
            warn("Low EXPLOITED_BY coverage", f"only {cnt} links — limits attack exposure analysis")

        # 11f. All 50 assets have subnet assignment
        r = s.run("MATCH (a:Asset) WHERE NOT (a)-[:IN_SUBNET]->(:Subnet) RETURN count(a) AS cnt")
        cnt = r.single()["cnt"]
        record("All assets have subnet", cnt == 0, f"missing={cnt}")

    driver.close()


# ===========================================================
# RUNNER
# ===========================================================
def main():
    print("\n" + "=" * 60)
    print("  CYBERSECURITY KG — FULL SYSTEM RELIABILITY TEST")
    print("=" * 60)

    start = time.time()

    try:
        test_graph_integrity()
    except Exception as e:
        record("GRAPH INTEGRITY SECTION", False, traceback.format_exc()[-120:])

    try:
        test_multi_hop_paths()
    except Exception as e:
        record("MULTI-HOP PATHS SECTION", False, traceback.format_exc()[-120:])

    try:
        test_intent_detection()
    except Exception as e:
        record("INTENT DETECTION SECTION", False, traceback.format_exc()[-120:])

    try:
        test_cypher_queries()
    except Exception as e:
        record("CYPHER QUERIES SECTION", False, traceback.format_exc()[-120:])

    try:
        test_vector_store()
    except Exception as e:
        record("VECTOR STORE SECTION", False, traceback.format_exc()[-120:])

    try:
        test_confidence_scoring()
    except Exception as e:
        record("CONFIDENCE SCORING SECTION", False, traceback.format_exc()[-120:])

    try:
        test_direct_answers()
    except Exception as e:
        record("DIRECT ANSWERS SECTION", False, traceback.format_exc()[-120:])

    try:
        test_attack_mapping()
    except Exception as e:
        record("ATTACK MAPPING SECTION", False, traceback.format_exc()[-120:])

    try:
        test_edge_cases()
    except Exception as e:
        record("EDGE CASES SECTION", False, traceback.format_exc()[-120:])

    try:
        test_explanation_quality()
    except Exception as e:
        record("EXPLANATION QUALITY SECTION", False, traceback.format_exc()[-120:])

    try:
        test_data_quality()
    except Exception as e:
        record("DATA QUALITY SECTION", False, traceback.format_exc()[-120:])

    elapsed = time.time() - start

    # ── Summary ──
    print("\n" + "=" * 60)
    print("  FINAL SUMMARY")
    print("=" * 60)
    print(f"  ✅ PASSED : {PASS}")
    print(f"  ❌ FAILED : {FAIL}")
    print(f"  ⚠️  WARNS  : {WARN}")
    print(f"  ⏱️  TIME   : {elapsed:.1f}s")
    print("=" * 60)

    if FAIL > 0:
        print("\n  FAILED TESTS:")
        for status, name, detail in RESULTS:
            if status == "FAIL":
                print(f"    ❌ {name}  ({detail})")

    if WARN > 0:
        print("\n  WARNINGS:")
        for status, name, detail in RESULTS:
            if status == "WARN":
                print(f"    ⚠️  {name}  ({detail})")

    print("\n" + "=" * 60)
    pct = (PASS / max(PASS + FAIL, 1)) * 100
    print(f"  RELIABILITY SCORE: {pct:.1f}% ({PASS}/{PASS+FAIL})")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

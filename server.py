"""
SecRAG-X — Flask API Server
Thin REST wrapper over the existing explane.py reasoning engine.
Now includes /api/graph endpoint that returns knowledge graph subgraphs.
Run:  python server.py
Open: http://localhost:5000
"""

import re
import traceback

from flask import Flask, jsonify, request, send_from_directory

from explane import (
    answer_question,
    attack_exposure_query,
    build_query,
    compare_assets_query,
    detect_intent,
    dos_risk_query,
    execute_query,
    extract_asset_id,
    extract_asset_ids,
    extract_software_name,
    highest_issues_query,
    malware_risk_query,
    map_to_attack,
    most_exposed_vulnerability_query,
    most_likely_attack_query,
    normalize_query_name,
    ransomware_systems_query,
    safest_system_query,
    software_risk_query,
    specific_software_risk_query,
    sql_injection_query,
    risky_software_systems_query,
    top_risks_query,
)

app = Flask(__name__, static_folder="static", static_url_path="")


# ── Frontend ────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# ── Graph helpers ───────────────────────────────────────────

def _add_node(nodes, nid, label, ntype, **extra):
    if nid and nid not in nodes:
        nodes[nid] = {"id": nid, "label": label or nid, "type": ntype, **extra}


def _add_edge(edges, seen, src, tgt, rel):
    if src and tgt:
        key = f"{src}|{tgt}|{rel}"
        if key not in seen:
            seen.add(key)
            edges.append({"source": src, "target": tgt, "type": rel})


def _graph_for_assets(asset_ids, cve_limit=10):
    """Build a knowledge subgraph for one or more assets."""
    nodes = {}
    edges = []
    seen = set()

    if not asset_ids:
        return {"nodes": [], "edges": []}

    query = """
    MATCH (a:Asset)
    WHERE a.id IN $ids
    OPTIONAL MATCH (a)-[:RUNS]->(s:Software)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(nb:Asset)
    WHERE nb.id IN $ids
    RETURN a.id AS aid, a.hostname AS ahost, a.department AS adept,
           a.criticality AS acrit,
           collect(DISTINCT {id: s.normalized, label: s.raw}) AS software,
           sn.id AS subnet,
           collect(DISTINCT nb.id) AS neighbors
    """
    try:
        rows = execute_query(query, {"ids": asset_ids})
    except Exception:
        traceback.print_exc()
        rows = []

    for row in rows:
        aid = row["aid"]
        _add_node(nodes, aid, row.get("ahost", aid), "Asset",
                  department=row.get("adept"), criticality=row.get("acrit"))

        for sw in (row.get("software") or []):
            if sw.get("id"):
                sid = f"sw_{sw['id']}"
                _add_node(nodes, sid, sw.get("label", sw["id"]), "Software")
                _add_edge(edges, seen, aid, sid, "RUNS")

        sn = row.get("subnet")
        if sn:
            snid = f"sn_{sn}"
            _add_node(nodes, snid, sn, "Subnet")
            _add_edge(edges, seen, aid, snid, "IN_SUBNET")

        for nb in (row.get("neighbors") or []):
            _add_edge(edges, seen, aid, nb, "CONNECTED_TO")

    # CVE / CWE / ATTACK chains
    cve_query = f"""
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    WHERE a.id IN $ids
    WITH a, c ORDER BY c.cvss DESC
    WITH a, collect(c)[0..{int(cve_limit)}] AS cves
    UNWIND cves AS c
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (cw)-[:EXPLOITED_BY]->(t:ATTACK)
    RETURN a.id AS aid, c.id AS cid, c.cvss AS cvss, c.severity AS sev,
           cw.id AS cwid, cw.name AS cwname,
           t.id AS tid, t.name AS tname
    """
    try:
        cve_rows = execute_query(cve_query, {"ids": asset_ids})
    except Exception:
        traceback.print_exc()
        cve_rows = []

    for row in cve_rows:
        cid = row.get("cid")
        if cid:
            _add_node(nodes, cid, cid, "CVE",
                      cvss=row.get("cvss"), severity=row.get("sev"))
            _add_edge(edges, seen, row["aid"], cid, "AFFECTED_BY")

        cwid = row.get("cwid")
        if cwid and cid:
            _add_node(nodes, cwid, row.get("cwname", cwid), "CWE")
            _add_edge(edges, seen, cid, cwid, "HAS_WEAKNESS")

        tid = row.get("tid")
        tname = row.get("tname")
        if tid and cwid:
            atk = f"atk_{tid}"
            _add_node(nodes, atk, tname or tid, "ATTACK")
            _add_edge(edges, seen, cwid, atk, "EXPLOITED_BY")

    return {"nodes": list(nodes.values()), "edges": edges}


def _graph_for_attack_type(attack_names, asset_limit=5):
    """Subgraph for attack-type queries (phishing, malware, etc.)."""
    nodes = {}
    edges = []
    seen = set()

    query = f"""
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)-[:HAS_WEAKNESS]->(cw:CWE)
          -[:EXPLOITED_BY]->(t:ATTACK)
    WHERE t.name IN $names
    WITH a, c, cw, t ORDER BY c.cvss DESC
    WITH a, collect(DISTINCT c)[0..5] AS cves,
         collect(DISTINCT cw)[0..5] AS cwes,
         collect(DISTINCT t) AS attacks
    LIMIT {int(asset_limit)}
    RETURN a.id AS aid, a.hostname AS ahost,
           [x IN cves | {{id: x.id, cvss: x.cvss, sev: x.severity}}] AS cves,
           [x IN cwes | {{id: x.id, name: x.name}}] AS cwes,
           [x IN attacks | {{id: x.id, name: x.name}}] AS attacks
    """
    try:
        rows = execute_query(query, {"names": attack_names})
    except Exception:
        traceback.print_exc()
        rows = []

    for row in rows:
        aid = row["aid"]
        _add_node(nodes, aid, row.get("ahost", aid), "Asset")

        for c in (row.get("cves") or []):
            _add_node(nodes, c["id"], c["id"], "CVE",
                      cvss=c.get("cvss"), severity=c.get("sev"))
            _add_edge(edges, seen, aid, c["id"], "AFFECTED_BY")

        for cw in (row.get("cwes") or []):
            _add_node(nodes, cw["id"], cw.get("name", cw["id"]), "CWE")
            # Link CVEs to CWEs
            for c in (row.get("cves") or []):
                _add_edge(edges, seen, c["id"], cw["id"], "HAS_WEAKNESS")

        for t in (row.get("attacks") or []):
            atk = f"atk_{t['id']}"
            _add_node(nodes, atk, t.get("name", t["id"]), "ATTACK")
            for cw in (row.get("cwes") or []):
                _add_edge(edges, seen, cw["id"], atk, "EXPLOITED_BY")

    return {"nodes": list(nodes.values()), "edges": edges}


def _top_asset_ids(n=3):
    try:
        rows = execute_query(top_risks_query(n))
        return [r["asset_id"] for r in rows if r.get("asset_id")]
    except Exception:
        return []


# ── API: Ask + Graph ───────────────────────────────────────

@app.route("/api/ask", methods=["POST"])
def api_ask():
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or "").strip()

    if not question:
        return jsonify({"error": "No question provided"}), 400

    # Get text answer
    try:
        answer = answer_question(question)
    except Exception as exc:
        traceback.print_exc()
        answer = (
            "Short answer:\n"
            "I could not answer because the backend could not be reached.\n\n"
            f"Technical detail: {exc}"
        )

    # Build graph subgraph based on intent
    try:
        intent = detect_intent(question)
        graph = _build_graph(intent, question)
    except Exception:
        traceback.print_exc()
        graph = {"nodes": [], "edges": []}

    return jsonify({"question": question, "answer": answer, "graph": graph})


def _asset_ids_from_query(cypher, params=None, key="asset_id", limit=5):
    """Run a Cypher query and extract asset IDs from the results."""
    try:
        rows = execute_query(cypher, params)
        ids = [r[key] for r in rows if r.get(key)]
        return ids[:limit]
    except Exception:
        traceback.print_exc()
        return []


def _build_graph(intent, query):
    # Intents that should NOT generate a knowledge graph —
    # these are education, out-of-scope, device, or status questions
    # that have no meaningful graph data to show.
    no_graph_intents = {
        "UNCLEAR_HELP",
        "OUT_OF_SCOPE_HELP",
        "EMPLOYEE_DEVICE_HELP",
        "COMPARE_ASSETS_MISSING_IDS_HELP",
        "ATTACK_STATUS",
        "PHISHING_EDUCATION_HELP",
        "MALWARE_EDUCATION_HELP",
        "ATTACK_IMPACT_EDUCATION_HELP",
    }
    if intent in no_graph_intents:
        return {"nodes": [], "edges": []}

    # ── Asset drilldown: show the exact asset from the question ──
    if intent == "ASSET_DRILLDOWN":
        aid = extract_asset_id(query)
        if aid:
            return _graph_for_assets([aid], cve_limit=12)

    # ── Compare assets: show the exact two assets being compared ──
    if intent == "COMPARE_ASSETS_HELP":
        aids = extract_asset_ids(query)
        if aids:
            return _graph_for_assets(aids, cve_limit=6)

    # ── Specific software risk: find assets affected by that software ──
    if intent == "SPECIFIC_SOFTWARE_RISK_HELP":
        sw = extract_software_name(query)
        if sw:
            ids = _asset_ids_from_query(
                specific_software_risk_query(),
                {"software": normalize_query_name(sw)},
                key="example_assets"
            )
            # example_assets is a list inside the row, flatten it
            try:
                rows = execute_query(specific_software_risk_query(),
                                     {"software": normalize_query_name(sw)})
                ids = []
                for r in rows:
                    ids.extend(r.get("example_assets") or [])
                if ids:
                    return _graph_for_assets(ids[:5], cve_limit=6)
            except Exception:
                pass

    # ── Top 10 risks: show same 10 assets as the text answer ──
    if intent == "TOP_10_RISKS_HELP":
        return _graph_for_assets(_top_asset_ids(10), cve_limit=4)

    # ── Top 5 most vulnerable: show same 5 assets ──
    if intent == "MOST_VULNERABLE_SYSTEMS_HELP":
        return _graph_for_assets(_top_asset_ids(5), cve_limit=5)

    # ── Highest issues: show the single asset with most issues ──
    if intent == "HIGHEST_ISSUES_HELP":
        ids = _asset_ids_from_query(highest_issues_query(), limit=1)
        if ids:
            return _graph_for_assets(ids, cve_limit=10)

    # ── Safest system: show the safest asset ──
    if intent == "SAFEST_SYSTEM_HELP":
        ids = _asset_ids_from_query(safest_system_query(), limit=1)
        if ids:
            return _graph_for_assets(ids, cve_limit=6)

    # ── Most exposed vulnerability: show the specific asset ──
    if intent == "MOST_EXPOSED_VULN_HELP":
        ids = _asset_ids_from_query(most_exposed_vulnerability_query(), limit=1)
        if ids:
            return _graph_for_assets(ids, cve_limit=8)

    # ── Software risk: find assets from the software risk query ──
    if intent == "SOFTWARE_RISK_HELP":
        try:
            rows = execute_query(software_risk_query(3))
            ids = []
            for r in rows:
                ids.extend(r.get("example_assets") or [])
            if ids:
                return _graph_for_assets(list(dict.fromkeys(ids))[:5], cve_limit=5)
        except Exception:
            pass

    # ── Risky software systems: show those specific assets ──
    if intent == "RISKY_SOFTWARE_SYSTEMS_HELP":
        ids = _asset_ids_from_query(risky_software_systems_query(5), limit=5)
        if ids:
            return _graph_for_assets(ids, cve_limit=5)

    # ── Attack exposure: show the exposed assets ──
    if intent == "ATTACK_EXPOSURE_HELP":
        ids = _asset_ids_from_query(attack_exposure_query(5), limit=5)
        if ids:
            return _graph_for_assets(ids, cve_limit=5)

    # ── Attack-type intents: use attack-specific queries ──
    if intent == "PHISHING_HELP":
        ids = _asset_ids_from_query(
            build_query("ATTACK_QUERY"), {"attack_list": ["Phishing"]}, limit=3
        )
        if ids:
            return _graph_for_assets(ids, cve_limit=6)

    if intent == "MALWARE_HELP":
        ids = _asset_ids_from_query(malware_risk_query(), limit=3)
        if ids:
            return _graph_for_assets(ids, cve_limit=6)

    if intent == "RANSOMWARE_SYSTEMS_HELP":
        ids = _asset_ids_from_query(ransomware_systems_query(5), limit=5)
        if ids:
            return _graph_for_assets(ids, cve_limit=5)

    if intent == "DOS_HELP":
        wants_list = any(x in query.lower() for x in ["which assets", "which systems", "assets", "systems", "list", "top"])
        limit = 5 if wants_list else 1
        ids = _asset_ids_from_query(dos_risk_query(limit), limit=limit)
        if ids:
            return _graph_for_assets(ids, cve_limit=6)

    if intent == "SQL_INJECTION_HELP":
        ids = _asset_ids_from_query(sql_injection_query(), limit=1)
        if ids:
            return _graph_for_assets(ids, cve_limit=8)

    if intent == "MOST_LIKELY_ATTACK_HELP":
        names = map_to_attack(query)
        if names:
            return _graph_for_attack_type(names)
        # Use the most_likely_attack_query to find top attack assets
        try:
            rows = execute_query(most_likely_attack_query(5))
            ids = []
            for r in rows:
                ids.extend(r.get("example_assets") or [])
            if ids:
                return _graph_for_assets(list(dict.fromkeys(ids))[:12], cve_limit=3)
        except Exception:
            pass

    # ── General asset intents: show same top assets as text ──
    general_intents = {
        "TOP_ASSETS", "GENERAL_RISK", "ATTACK_SURFACE", "ATTACK_QUERY",
        "MOST_VULNERABLE_HELP",
        "SYSTEM_SAFETY_HELP", "SYSTEM_CONCERN_HELP",
        "SERVER_RISK_HELP",
        "VAGUE_SYSTEM_VULNERABLE_HELP",
    }
    if intent in general_intents:
        return _graph_for_assets(_top_asset_ids(3), cve_limit=6)

    # For any other unrecognized intent, do NOT generate a random graph
    return {"nodes": [], "edges": []}


# ── API: Graph summary stats ──────────────────────────────

@app.route("/api/summary")
def api_summary():
    query = """
    CALL () { MATCH (a:Asset) RETURN count(a) AS assets }
    CALL () { MATCH (:Asset)-[r:AFFECTED_BY]->(:CVE) RETURN count(r) AS asset_cve_links }
    CALL () { MATCH (:CVE) RETURN count(*) AS cves }
    CALL () { MATCH (:CWE) RETURN count(*) AS weaknesses }
    CALL () { MATCH (:ATTACK) RETURN count(*) AS attacks }
    RETURN assets, asset_cve_links, cves, weaknesses, attacks
    """
    try:
        rows = execute_query(query)
        data = rows[0] if rows else {}
    except Exception:
        data = {}

    defaults = {"assets": 0, "asset_cve_links": 0, "cves": 0,
                "weaknesses": 0, "attacks": 0}
    return jsonify({**defaults, **data})


# ── API: Top risk assets ──────────────────────────────────

@app.route("/api/risks")
def api_risks():
    limit = max(1, min(request.args.get("limit", 10, type=int), 50))
    try:
        rows = execute_query(top_risks_query(limit))
    except Exception:
        rows = []
    return jsonify(rows)


# ── API: Attack categories ────────────────────────────────

@app.route("/api/attacks")
def api_attacks():
    limit = max(1, min(request.args.get("limit", 5, type=int), 20))
    try:
        rows = execute_query(most_likely_attack_query(limit))
    except Exception:
        rows = []
    return jsonify(rows)


# ── API: Exposure ─────────────────────────────────────────

@app.route("/api/exposure")
def api_exposure():
    limit = max(1, min(request.args.get("limit", 5, type=int), 20))
    try:
        rows = execute_query(attack_exposure_query(limit))
    except Exception:
        rows = []
    return jsonify(rows)


# ── API: Asset lookup ─────────────────────────────────────

@app.route("/api/asset/<asset_id>")
def api_asset(asset_id):
    asset_id = asset_id.strip().upper()
    if not re.match(r"^SRV-\d+$", asset_id):
        return jsonify({"error": "Invalid asset ID format."}), 400

    query = """
    MATCH (a:Asset {id:$asset_id})
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    OPTIONAL MATCH (a)-[r:AFFECTED_BY]->(c:CVE)
    WITH a, sn,
         count(DISTINCT neighbor) AS connected_systems,
         count(DISTINCT c) AS known_issues,
         max(c.cvss) AS highest_score,
         collect(DISTINCT coalesce(r.software_raw, r.software))[0..6] AS software,
         collect(DISTINCT c.id)[0..8] AS example_cves
    RETURN a.id AS asset_id, a.hostname AS hostname,
           a.department AS department, a.criticality AS criticality,
           sn.id AS subnet, connected_systems, known_issues,
           round(coalesce(highest_score, 0) * 10) / 10 AS highest_score,
           software, example_cves
    """
    try:
        rows = execute_query(query, {"asset_id": asset_id})
    except Exception:
        rows = []

    if not rows:
        return jsonify({"error": "No asset found with that ID."}), 404
    return jsonify(rows[0])


# ── API: Health ───────────────────────────────────────────

@app.route("/api/health")
def api_health():
    queries = {
        "relationships": "MATCH ()-[r]->() RETURN type(r) AS relationship, count(r) AS count ORDER BY relationship",
        "confidence": """MATCH (:Asset)-[r:AFFECTED_BY]->(:CVE)
            RETURN r.source AS source, r.confidence AS confidence,
                   r.match_level AS match_level, count(r) AS count
            ORDER BY confidence, match_level""",
        "weak_links": """MATCH ()-[r]->()
            WHERE r.source = 'description' OR type(r) = 'HAS_VULN'
            RETURN type(r) AS relationship, r.source AS source, count(r) AS count""",
    }
    result = {}
    for key, q in queries.items():
        try:
            result[key] = execute_query(q)
        except Exception:
            result[key] = []
    return jsonify(result)


# ── Run ───────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  SecRAG-X server starting...")
    print("  Open http://localhost:5000 in your browser\n")
    app.run(host="0.0.0.0", port=5000, debug=False)

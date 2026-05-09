"""Test the exact graph-building flow from server.py"""
import traceback
from explane import execute_query, detect_intent, extract_asset_id, map_to_attack

# Replicate _graph_for_assets from server.py
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
        print(f"Asset query returned {len(rows)} rows")
        for r in rows[:2]:
            print("  Row:", r)
    except Exception as e:
        print(f"Asset query FAILED: {e}")
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

    # CVE query
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
        print(f"CVE query returned {len(cve_rows)} rows")
    except Exception as e:
        print(f"CVE query FAILED: {e}")
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


# Test
print("=" * 60)
print("Testing graph for SRV-032")
print("=" * 60)
graph = _graph_for_assets(["SRV-032"], cve_limit=10)
print(f"\nFinal graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
for n in graph['nodes'][:5]:
    print(f"  Node: {n['type']} - {n['label']}")
for e in graph['edges'][:5]:
    print(f"  Edge: {e['source']} --{e['type']}--> {e['target']}")

"""Test: graph assets must match text answer assets."""
import requests, re

def extract_text_assets(text):
    """Pull SRV-xxx IDs from the text answer."""
    return sorted(set(re.findall(r"SRV-\d+", text)))

def extract_graph_assets(graph):
    """Pull asset IDs from graph nodes."""
    return sorted(set(
        n["id"] for n in graph.get("nodes", []) if n.get("type") == "Asset"
    ))

tests = [
    "why is SRV-032 risky",
    "is mysql causing issues",
    "which is more risky SRV-032 or SRV-049",
    "list top 5 most vulnerable assets",
    "which system has the highest issues",
    "which system is safest",
    "ddos vulnerable assets",
    "top 5 attacks dangerous for my system",
]

for q in tests:
    r = requests.post("http://localhost:5000/api/ask", json={"question": q})
    data = r.json()
    text_assets = extract_text_assets(data.get("answer", ""))
    graph_assets = extract_graph_assets(data.get("graph", {}))
    
    # Check if text assets appear in graph
    text_in_graph = all(a in graph_assets for a in text_assets) if text_assets else True
    status = "PASS" if text_in_graph else "FAIL"
    
    print(f"[{status}] \"{q}\"")
    print(f"  Text assets:  {text_assets}")
    print(f"  Graph assets: {graph_assets}")
    if not text_in_graph:
        missing = [a for a in text_assets if a not in graph_assets]
        print(f"  MISSING from graph: {missing}")
    print()

"""Test the /api/ask endpoint directly via requests."""
import requests
import json

r = requests.post("http://localhost:5000/api/ask", json={"question": "why is SRV-032 risky"})
data = r.json()

print("Status:", r.status_code)
print("Has answer:", bool(data.get("answer")))
print("Graph key present:", "graph" in data)
graph = data.get("graph")
if graph:
    print(f"Graph nodes: {len(graph.get('nodes', []))}")
    print(f"Graph edges: {len(graph.get('edges', []))}")
    for n in graph.get("nodes", [])[:3]:
        print(f"  Node: {n}")
else:
    print("Graph is:", repr(graph))
    print("Full response keys:", list(data.keys()))
    print("Answer preview:", data.get("answer", "")[:200])

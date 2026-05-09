"""Test: non-security questions should NOT generate a graph."""
import requests

tests = [
    ("i am facing an issue in my mobile phone", False),
    ("tell me something random", False),
    ("what happens if system is attacked", False),
    ("am i safe from phishing", False),
    ("is my system under attack", False),
    ("why is malware dangerous", False),
    ("why is SRV-032 risky", True),
    ("list top 5 most vulnerable assets", True),
    ("is mysql causing issues", True),
    ("ddos vulnerable assets", True),
]

for question, expect_graph in tests:
    r = requests.post("http://localhost:5000/api/ask", json={"question": question})
    data = r.json()
    graph = data.get("graph", {})
    node_count = len(graph.get("nodes", []))
    has_graph = node_count > 0
    status = "PASS" if has_graph == expect_graph else "FAIL"
    print(f"[{status}] \"{question}\" -> {node_count} nodes (expect {'graph' if expect_graph else 'no graph'})")

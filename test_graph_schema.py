"""Quick graph schema test - counts nodes and relationships."""
from neo4j import GraphDatabase

d = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "12345678"))
s = d.session()

# Node counts
r = s.run("MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt ORDER BY cnt DESC")
print("=== NODE COUNTS ===")
for rec in r:
    print(f"  {rec['label']}: {rec['cnt']}")

# Relationship counts
r2 = s.run("MATCH ()-[r]->() RETURN type(r) AS rel, count(r) AS cnt ORDER BY cnt DESC")
print("\n=== RELATIONSHIP COUNTS ===")
for rec in r2:
    print(f"  {rec['rel']}: {rec['cnt']}")

s.close()
d.close()

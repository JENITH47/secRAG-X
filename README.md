# SecRAG-X

SecRAG-X is a cybersecurity reasoning prototype that combines a Neo4j knowledge graph, FAISS vector search, and an Ollama-backed language model to answer enterprise security questions with graph context.

The system connects assets, software, subnets, CVEs, CWEs, and MITRE ATT&CK techniques so users can ask practical questions such as which systems are most exposed, why an asset is risky, or which attack paths are likely in the current environment.

## Highlights

- Knowledge graph for enterprise assets, software inventory, vulnerabilities, weaknesses, network topology, and attack techniques.
- Retrieval-augmented reasoning with FAISS and Ollama embeddings.
- Flask API with a browser dashboard for questions, graph visualization, risk summaries, and asset drilldowns.
- Intent detection and defensive guidance for vague, unsafe, or out-of-scope user queries.
- Data ingestion scripts for cleaned CVE, CWE, CPE, MITRE ATT&CK, and enterprise asset datasets.
- Tests for API behavior, graph schema, alignment, reasoning flow, and no-graph fallback cases.

## Architecture

```text
User / Dashboard
      |
      v
Flask API (server.py)
      |
      v
Reasoning Engine (explane.py)
      |
      +-- Neo4j Knowledge Graph
      +-- FAISS Vector Store
      +-- Ollama LLM / Embeddings
```

## Project Structure

```text
static/                  Browser dashboard
server.py                Flask API and graph endpoints
explane.py               Main reasoning and intent engine
data_ingest.py           Neo4j ingestion pipeline
build_knowledge.py       FAISS knowledge base builder
vector_store.py          Embedding and vector search helpers
rag_engine.py            Lightweight RAG wrapper
mapping_engine.py        Graph mapping utilities
asset.py                 Mock enterprise asset generator
network_topology.py      Mock topology/SBOM generator
test_*.py                Validation and regression tests
```

## Requirements

- Python 3.8 or newer
- Neo4j running locally or reachable over Bolt
- Ollama running locally
- Ollama embedding model: `nomic-embed-text`

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Pull the embedding model if needed:

```bash
ollama pull nomic-embed-text
```

## Configuration

The app reads Neo4j settings from environment variables and falls back to local development defaults:

```bash
set NEO4J_URI=bolt://127.0.0.1:7687
set NEO4J_USERNAME=neo4j
set NEO4J_PASSWORD=12345678
```

On macOS/Linux, use `export` instead of `set`.

## Setup

1. Start Neo4j and Ollama.
2. Install dependencies.
3. Ingest graph data:

```bash
python data_ingest.py
```

4. Build the FAISS knowledge index:

```bash
python build_knowledge.py
```

5. Run the dashboard and API:

```bash
python server.py
```

Open `http://localhost:5000` in your browser.

## API

- `POST /api/ask` answers a natural language security question and returns graph context.
- `GET /api/summary` returns graph totals for assets, CVEs, weaknesses, and attacks.
- `GET /api/risks` returns the highest-risk assets.
- `GET /api/attacks` returns likely attack techniques.
- `GET /api/exposure` returns attack exposure metrics.
- `GET /api/asset/<asset_id>` returns detailed context for a single asset.

Example:

```bash
curl -X POST http://localhost:5000/api/ask ^
  -H "Content-Type: application/json" ^
  -d "{\"question\":\"Which systems are most vulnerable?\"}"
```

## Example Questions

- Which systems are most vulnerable?
- Why is SRV-042 risky?
- Is SRV-010 at risk from ransomware?
- Compare the risk between SRV-010 and SRV-015.
- Which software creates the most exposure?

## Testing

Run the focused test suite after Neo4j is populated:

```bash
python test_api.py
python test_graph_schema.py
python test_alignment.py
python test_no_graph.py
```

For broader validation:

```bash
python test_full_system.py
```

## Notes

- Large/generated datasets and vector index files are intentionally excluded from git.
- Generated reports, temporary render output, Python caches, and local environment files are ignored by git.
- Keep real production credentials out of source control; use environment variables for local configuration.

import ollama
import numpy as np
from knowledge_base import load_knowledge


def embed(text):
    response = ollama.embeddings(
        model="nomic-embed-text",
        prompt=text
    )
    return np.array(response["embedding"])


def similarity(a, b):
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


def build_index():
    knowledge = load_knowledge()
    index = []

    for item in knowledge:
        vec = embed(item["text"])
        index.append({
            "text": item["text"],
            "vector": vec
        })

    return index


def retrieve(query, index, top_k=2):

    q_vec = embed(query)

    scored = []
    for item in index:
        score = similarity(q_vec, item["vector"])
        scored.append((score, item["text"]))

    scored.sort(reverse=True, key=lambda x: x[0])

    return [x[1] for x in scored[:top_k]]
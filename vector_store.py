import faiss
import numpy as np
import ollama
import pickle
import os

DB_PATH = "vector.index"
META_PATH = "metadata.pkl"


def embed(text):
    response = ollama.embeddings(
        model="nomic-embed-text",
        prompt=text,
    )
    return np.array(response["embedding"]).astype("float32")


def build_vector_db(texts):
    vectors = [embed(t) for t in texts]
    dim = len(vectors[0])

    index = faiss.IndexFlatL2(dim)
    index.add(np.array(vectors))

    faiss.write_index(index, DB_PATH)

    with open(META_PATH, "wb") as f:
        pickle.dump(texts, f)

    print("Vector DB built")


def load_vector_db():
    if not os.path.exists(DB_PATH):
        return None, None

    index = faiss.read_index(DB_PATH)

    with open(META_PATH, "rb") as f:
        texts = pickle.load(f)

    return index, texts


def retrieve(query, index, texts, k=2):
    q_vec = embed(query).reshape(1, -1)
    distances, indices = index.search(q_vec, k)
    return [texts[i] for i in indices[0]]

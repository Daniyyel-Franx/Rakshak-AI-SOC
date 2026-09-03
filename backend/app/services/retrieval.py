"""Local RAG retrieval over approved knowledge.

Prefers FAISS + a local embedding model when available (EMBEDDING_MODEL_PATH),
otherwise falls back to deterministic keyword retrieval. Retrieval respects
approval_state, classification and site compatibility. No external embedding
API is ever contacted.
"""
from __future__ import annotations

import json
import logging
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..config import KNOWLEDGE_DIR, settings

logger = logging.getLogger("rakshak.retrieval")

_KNOWLEDGE_FILES = [
    "attack_techniques.json",
    "sigma_rules.json",
    "playbooks.json",
    "schema_docs.json",
]


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


@lru_cache
def load_documents() -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for fname in _KNOWLEDGE_FILES:
        path = KNOWLEDGE_DIR / fname
        if not path.exists():
            continue
        raw = json.loads(path.read_text())
        items = raw if isinstance(raw, list) else raw.get("items", [])
        for item in items:
            item.setdefault("source", fname)
            item.setdefault("classification", "unclassified")
            item.setdefault("approval_state", "approved")
            item.setdefault("site_id", "*")
            item.setdefault("version", "1.0")
            docs.append(item)
    return docs


def _allowed(doc: dict[str, Any], clearance: str, site_id: str) -> bool:
    if doc.get("approval_state") != "approved":
        return False
    levels = {"unclassified": 0, "restricted": 1, "confidential": 2, "secret": 3}
    if levels.get(doc.get("classification", "unclassified"), 0) > levels.get(clearance, 0):
        return False
    ds = doc.get("site_id", "*")
    if ds not in ("*", site_id):
        return False
    return True


def faiss_available() -> bool:
    if not settings.embedding_model_path:
        return False
    try:
        import faiss  # noqa: F401
        return Path(settings.embedding_model_path).exists()
    except Exception:
        return False


def retrieve(query: str, *, clearance: str = "unclassified", site_id: str = "*",
             top_k: int = 5) -> dict[str, Any]:
    """Return {mode, results:[{document_id, text, source, score}]}."""
    docs = [d for d in load_documents() if _allowed(d, clearance, site_id)]
    if faiss_available():
        try:
            return {"mode": "faiss", "results": _faiss_retrieve(query, docs, top_k)}
        except Exception as exc:
            logger.info("faiss retrieve failed, using keyword: %s", type(exc).__name__)
    return {"mode": "keyword", "results": _keyword_retrieve(query, docs, top_k)}


def _doc_text(d: dict[str, Any]) -> str:
    return " ".join(str(d.get(k, "")) for k in ("title", "name", "summary", "description",
                                                 "text", "logsource", "detection", "id"))


def _keyword_retrieve(query: str, docs: list[dict[str, Any]], top_k: int) -> list[dict[str, Any]]:
    q_tokens = set(_tokenize(query))
    scored = []
    for d in docs:
        text = _doc_text(d)
        d_tokens = _tokenize(text)
        if not d_tokens:
            continue
        overlap = sum(1 for t in d_tokens if t in q_tokens)
        # tf-lite score with length normalisation
        score = overlap / math.sqrt(len(d_tokens))
        if score > 0:
            scored.append((score, d, text))
    scored.sort(key=lambda x: (-x[0], x[1].get("document_id", x[1].get("id", ""))))
    return [
        {
            "document_id": d.get("document_id", d.get("id", "")),
            "text": text[:600],
            "source": d.get("source"),
            "classification": d.get("classification"),
            "score": round(score, 4),
        }
        for score, d, text in scored[:top_k]
    ]


def _faiss_retrieve(query: str, docs: list[dict[str, Any]], top_k: int) -> list[dict[str, Any]]:
    import faiss  # type: ignore
    import numpy as np
    from sentence_transformers import SentenceTransformer  # type: ignore

    model = SentenceTransformer(settings.embedding_model_path)
    texts = [_doc_text(d) for d in docs]
    embeddings = model.encode(texts, normalize_embeddings=True)
    index = faiss.IndexFlatIP(embeddings.shape[1])
    index.add(np.asarray(embeddings, dtype="float32"))
    q_emb = model.encode([query], normalize_embeddings=True).astype("float32")
    scores, idxs = index.search(q_emb, min(top_k, len(docs)))
    out = []
    for score, idx in zip(scores[0], idxs[0]):
        d = docs[idx]
        out.append({
            "document_id": d.get("document_id", d.get("id", "")),
            "text": texts[idx][:600],
            "source": d.get("source"),
            "classification": d.get("classification"),
            "score": round(float(score), 4),
        })
    return out

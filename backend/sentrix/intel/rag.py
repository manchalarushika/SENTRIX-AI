"""Threat Intelligence RAG (retrieval-augmented generation).

Retrieval is deterministic: a TF-IDF index (scikit-learn, word 1-2 grams with
sub-linear TF) is built over every ``IntelDocument`` and queried with cosine
similarity. Exact identifier matches (``T1059.001``, ``CVE-2021-44228``) get a
boost so structured lookups work reliably.

Generation is optional: when an LLM is configured, the retrieved passages are
passed as the *only* allowed context and the model must cite document IDs.
Without an LLM the API returns the ranked passages and an extractive summary.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentrix.db.models import IntelDocument
from sentrix.llm.client import LLMError, llm

_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?|CVE-\d{4}-\d{4,7}|PB-[A-Z]+)\b", re.I)


@dataclass
class _Index:
    signature: tuple[int, int]
    vectorizer: TfidfVectorizer
    matrix: Any
    docs: list[dict[str, Any]]


class IntelRetriever:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._index: _Index | None = None

    def _signature(self, db: Session) -> tuple[int, int]:
        count = db.scalar(select(func.count(IntelDocument.id))) or 0
        max_id = db.scalar(select(func.max(IntelDocument.id))) or 0
        return count, max_id

    def _build(self, db: Session) -> _Index | None:
        sig = self._signature(db)
        with self._lock:
            if self._index is not None and self._index.signature == sig:
                return self._index
            rows = db.scalars(select(IntelDocument).order_by(IntelDocument.id)).all()
            if not rows:
                self._index = None
                return None
            docs = [
                {
                    "doc_id": r.doc_id,
                    "doc_type": r.doc_type,
                    "title": r.title,
                    "body": r.body,
                    "tags": r.tags or [],
                    "source": r.source,
                    "url": r.url,
                }
                for r in rows
            ]
            corpus = [f"{d['title']} {d['title']} {' '.join(d['tags'])} {d['body']}" for d in docs]
            vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english",
                                  token_pattern=r"(?u)\b[\w.\-]{2,}\b")
            matrix = vec.fit_transform(corpus)
            self._index = _Index(sig, vec, matrix, docs)
            return self._index

    def invalidate(self) -> None:
        with self._lock:
            self._index = None

    def search(
        self, db: Session, query: str, top_k: int = 5, doc_types: list[str] | None = None
    ) -> list[dict[str, Any]]:
        idx = self._build(db)
        if idx is None:
            return []
        scores = linear_kernel(idx.vectorizer.transform([query]), idx.matrix).ravel()
        ids = {m.upper() for m in _ID_RE.findall(query)}
        results = []
        for i, d in enumerate(idx.docs):
            if doc_types and d["doc_type"] not in doc_types:
                continue
            s = float(scores[i])
            if d["doc_id"].upper() in ids:
                s += 1.0
            elif any(d["doc_id"].upper().startswith(x + ".") for x in ids):
                s += 0.3
            if s > 0.01:
                results.append((s, d))
        results.sort(key=lambda x: x[0], reverse=True)
        return [{**d, "score": round(s, 4)} for s, d in results[:top_k]]


retriever = IntelRetriever()


def _extractive_summary(query: str, docs: list[dict[str, Any]]) -> str:
    if not docs:
        return "No relevant threat-intelligence documents were found."
    terms = {t.lower() for t in re.findall(r"\w{4,}", query)}
    lines = []
    for d in docs[:3]:
        sentences = re.split(r"(?<=[.!?])\s+|\n", d["body"])
        best = max(sentences, key=lambda s: sum(t in s.lower() for t in terms), default="")
        lines.append(f"[{d['doc_id']}] {best.strip()}")
    return "\n".join(lines)


def answer(db: Session, query: str, top_k: int = 5, synthesize: bool = False) -> dict[str, Any]:
    docs = retriever.search(db, query, top_k=top_k)
    result: dict[str, Any] = {
        "query": query,
        "documents": docs,
        "retrieval": "tf-idf cosine similarity (deterministic)",
        "answer": _extractive_summary(query, docs),
        "answer_method": "extractive",
    }
    if synthesize and docs:
        if not llm.available:
            result["llm"] = {"status": "disabled", "reason": "No LLM provider configured"}
            return result
        context = "\n\n".join(f"[{d['doc_id']}] {d['title']}\n{d['body'][:1500]}" for d in docs)
        try:
            resp = llm.complete(
                system=(
                    "You are a threat-intelligence analyst. Answer ONLY from the provided documents. "
                    "Cite document IDs in square brackets after each claim. If the documents do not "
                    "contain the answer, say so explicitly. Be concise."
                ),
                prompt=f"Documents:\n{context}\n\nQuestion: {query}",
            )
            result["answer"] = resp.text
            result["answer_method"] = "llm-synthesis (grounded in retrieved documents)"
            result["llm"] = {"status": "ok", "provider": resp.provider, "model": resp.model,
                             "latency_ms": resp.latency_ms}
        except LLMError as exc:
            result["llm"] = {"status": "error", "reason": str(exc)}
    return result

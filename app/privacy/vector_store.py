from __future__ import annotations

import chromadb

COLLECTION_NAME = "personal_agent_firewall_pii_examples"

DEFAULT_DISTANCE_THRESHOLD = 0.6

SENSITIVE_EXAMPLES = [
    "my social security number is",
    "here is my private key",
    "this is my password",
    "confidential financial report attached",
    "my credit card number is",
    "my bank account number is",
    "here is my API key",
    "my date of birth is",
    "this document contains personal medical information",
    "my home address is",
    "here is my username and password for the account",
    "this is a confidential internal document, do not share",
    "this file contains a list of customer names and contact information",
]


class SemanticPiiDetector:
    """Cosine-similarity PII/secret detector using Chroma's local embedding model.

    Catches natural-language sensitive content that fixed regex patterns
    miss (e.g. "here is my private key for the wallet" has no fixed format
    to match against). Runs entirely locally via Chroma's bundled
    all-MiniLM-L6-v2 embedding model -- no external embedding API key
    required. The first call in a process downloads that model (~80MB,
    cached under ~/.cache/chroma/); every call after that is local-only.
    """

    def __init__(
        self,
        distance_threshold: float = DEFAULT_DISTANCE_THRESHOLD,
        client=None,
    ):
        self._threshold = distance_threshold
        self._client = client or chromadb.Client()
        self._collection = self._client.get_or_create_collection(
            COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
        )
        if self._collection.count() == 0:
            self._collection.add(
                documents=SENSITIVE_EXAMPLES,
                ids=[f"seed-{i}" for i in range(len(SENSITIVE_EXAMPLES))],
            )

    def is_sensitive(self, text: str) -> bool:
        if not text or not text.strip():
            return False
        result = self._collection.query(query_texts=[text], n_results=1)
        distances = result.get("distances") or [[]]
        if not distances or not distances[0]:
            return False
        return distances[0][0] <= self._threshold

"""テスト用の決定的なEmbedding function (外部APIを呼ばない)。"""

import hashlib

import numpy as np
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

_DIMENSIONS = 64


class FakeEmbeddingFunction(EmbeddingFunction[Documents]):
    """単語のハッシュによるbag-of-wordsベクトルを返す。呼び出し件数を記録する。"""

    def __init__(self, *, fail: bool = False) -> None:
        self.embedded_count = 0
        self.fail = fail

    def __call__(self, input: Documents) -> Embeddings:  # noqa: A002
        if self.fail:
            err_msg = "embedding failed"
            raise RuntimeError(err_msg)
        self.embedded_count += len(input)
        vectors = []
        for text in input:
            vector = np.zeros(_DIMENSIONS, dtype=np.float32)
            for word in text.lower().split():
                vector[int(hashlib.md5(word.encode()).hexdigest(), 16) % _DIMENSIONS] += 1.0  # noqa: S324
            vectors.append(vector / (np.linalg.norm(vector) or 1.0))
        return vectors

    @staticmethod
    def name() -> str:
        return "fake"

    def get_config(self) -> dict[str, object]:
        return {}

    @staticmethod
    def build_from_config(config: dict[str, object]) -> "FakeEmbeddingFunction":  # noqa: ARG004
        return FakeEmbeddingFunction()

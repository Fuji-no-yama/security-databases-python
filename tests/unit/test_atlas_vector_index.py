from pathlib import Path

import pytest

from atlas import vector_index
from atlas.vector_index import AtlasVectorIndex, IndexSpec
from tests.fake_embedding import FakeEmbeddingFunction

SPEC = IndexSpec(name="atlas_test", ids=["a", "b"], documents=["prompt injection attack", "model theft"])


def test_builds_collection_and_returns_similarities(tmp_path: Path) -> None:
    index = AtlasVectorIndex(tmp_path, FakeEmbeddingFunction(), data_hash="h1")
    index.ensure([SPEC])

    similarities = index.similarities("atlas_test", "prompt injection")

    assert set(similarities) == {"a", "b"}
    assert similarities["a"] > similarities["b"]


def test_reuses_collection_when_unchanged(tmp_path: Path) -> None:
    AtlasVectorIndex(tmp_path, FakeEmbeddingFunction(), data_hash="h1").ensure([SPEC])
    embedding_function = FakeEmbeddingFunction()

    AtlasVectorIndex(tmp_path, embedding_function, data_hash="h1").ensure([SPEC])

    assert embedding_function.embedded_count == 0


def test_rebuilds_when_data_hash_changes(tmp_path: Path) -> None:
    AtlasVectorIndex(tmp_path, FakeEmbeddingFunction(), data_hash="h1").ensure([SPEC])
    embedding_function = FakeEmbeddingFunction()

    AtlasVectorIndex(tmp_path, embedding_function, data_hash="h2").ensure([SPEC])

    assert embedding_function.embedded_count == len(SPEC.ids)


def test_rebuilds_when_index_version_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    AtlasVectorIndex(tmp_path, FakeEmbeddingFunction(), data_hash="h1").ensure([SPEC])
    monkeypatch.setattr(vector_index, "INDEX_VERSION", "999")
    embedding_function = FakeEmbeddingFunction()

    AtlasVectorIndex(tmp_path, embedding_function, data_hash="h1").ensure([SPEC])

    assert embedding_function.embedded_count == len(SPEC.ids)


def test_removes_collections_not_in_specs(tmp_path: Path) -> None:
    index = AtlasVectorIndex(tmp_path, FakeEmbeddingFunction(), data_hash="h1")
    index.ensure([SPEC, IndexSpec(name="atlas_casestudy", ids=["x"], documents=["old"])])

    index.ensure([SPEC])

    names = {c.name for c in index._client.list_collections()}  # noqa: SLF001
    assert names == {"atlas_test"}


def test_failed_build_leaves_no_partial_collection(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="embedding failed"):
        AtlasVectorIndex(tmp_path, FakeEmbeddingFunction(fail=True), data_hash="h1").ensure([SPEC])

    embedding_function = FakeEmbeddingFunction()
    AtlasVectorIndex(tmp_path, embedding_function, data_hash="h1").ensure([SPEC])

    assert embedding_function.embedded_count == len(SPEC.ids)

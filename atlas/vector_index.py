"""ATLASのベクトルDB(Chroma)の作成・自動再構築・類似度検索を管理する。"""

import logging
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import chromadb
from chromadb.errors import NotFoundError
from tqdm import tqdm

if TYPE_CHECKING:
    from chromadb.api.client import ClientAPI
    from chromadb.api.models.Collection import Collection

logger = logging.getLogger("atlas")

# ベクトル化する文章の作り方やコレクション構成を変えたら上げる。
# 既存利用者のベクトルDBは次回起動時に自動で再構築される。
INDEX_VERSION = "2"

_BUILDING_SUFFIX = "__building"
_CHUNK_SIZE = 200


@dataclass(frozen=True)
class IndexSpec:
    """
    1コレクション分のベクトル化対象。

    Args:
        name (str): コレクション名
        ids (list[str]): ドキュメントID
        documents (list[str]): ベクトル化するテキスト
    """

    name: str
    ids: list[str]
    documents: list[str]


class AtlasVectorIndex:
    """
    ChromaのコレクションをIndexSpecに合わせて維持するクラス。

    各コレクションのメタデータに index_version と data_hash を記録し、
    起動時に現在の値と異なる(またはコレクションが無い)場合はそのコレクションだけ再構築する。

    Args:
        path (Path): Chromaの永続化ディレクトリ
        embedding_function (Any): ChromaのEmbedding function
        data_hash (str): ATLASデータファイルのハッシュ
        show_progress (bool): 再構築時に進捗バーを標準エラー出力に表示するか
    """

    def __init__(self, path: Path, embedding_function: Any, data_hash: str, *, show_progress: bool = False) -> None:  # noqa: ANN401
        self._client: ClientAPI = chromadb.PersistentClient(str(path))
        self._embedding_function = embedding_function
        self._data_hash = data_hash
        self._show_progress = show_progress
        self._collections: dict[str, Collection] = {}

    def _expected_metadata(self) -> dict[str, str]:
        return {"hnsw:space": "cosine", "index_version": INDEX_VERSION, "data_hash": self._data_hash}

    def _is_current(self, name: str) -> bool:
        try:
            collection = self._client.get_collection(name=name, embedding_function=self._embedding_function)
        except (NotFoundError, ValueError):
            return False
        metadata = collection.metadata or {}
        expected = self._expected_metadata()
        return all(metadata.get(key) == expected[key] for key in ("index_version", "data_hash"))

    def ensure(self, specs: list[IndexSpec], *, force_rebuild: bool = False) -> None:
        """
        各コレクションが最新であることを保証し、古い・存在しないものを再構築する。

        specsに無いコレクション(旧バージョンのコレクションや中断した再構築の残骸)は削除する。

        Args:
            specs (list[IndexSpec]): 維持するコレクション一覧
            force_rebuild (bool): Trueなら全コレクションを再構築する
        """
        expected_names = {spec.name for spec in specs}
        for collection in self._client.list_collections():
            name = collection if isinstance(collection, str) else collection.name
            if name not in expected_names:
                logger.info("不要なコレクション '%s' を削除します。", name)
                self._client.delete_collection(name=name)

        for spec in specs:
            if force_rebuild or not self._is_current(spec.name):
                self._rebuild(spec)
            self._collections[spec.name] = self._client.get_collection(name=spec.name, embedding_function=self._embedding_function)

    def _rebuild(self, spec: IndexSpec) -> None:
        logger.info("ベクトルDB '%s' を構築します (%d件)。", spec.name, len(spec.ids))
        building_name = f"{spec.name}{_BUILDING_SUFFIX}"
        with suppress(NotFoundError, ValueError):
            self._client.delete_collection(name=building_name)
        building = self._client.create_collection(
            name=building_name,
            metadata=self._expected_metadata(),
            embedding_function=self._embedding_function,
        )
        try:
            for start in tqdm(
                range(0, len(spec.ids), _CHUNK_SIZE),
                desc=spec.name,
                disable=not self._show_progress,
                file=sys.stderr,
            ):
                end = start + _CHUNK_SIZE
                building.add(ids=spec.ids[start:end], documents=spec.documents[start:end])
        except Exception:
            self._client.delete_collection(name=building_name)
            raise
        # 全件の追加が終わってから正式名に差し替えるため、途中で失敗しても不完全なコレクションは残らない
        with suppress(NotFoundError, ValueError):
            self._client.delete_collection(name=spec.name)
        building.modify(name=spec.name)
        logger.info("ベクトルDB '%s' の構築が完了しました。", spec.name)

    def similarities(self, name: str, query: str) -> dict[str, float]:
        """
        クエリとコレクション内の全ドキュメントのcos類似度を返す。

        Args:
            name (str): コレクション名
            query (str): 検索文言

        Returns:
            dict[str, float]: ID -> cos類似度 (1 - cos距離)
        """
        collection = self._collections[name]
        count = collection.count()
        if count == 0:
            return {}
        result = collection.query(query_texts=[query], n_results=count, include=["distances"])
        distances = result.get("distances") or [[]]
        return {doc_id: 1.0 - float(dist) for doc_id, dist in zip(result["ids"][0], distances[0], strict=True)}

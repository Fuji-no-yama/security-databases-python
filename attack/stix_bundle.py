"""MITRE ATT&CKの公式STIX 2.1バンドルを読み込み、検索しやすい形に索引付けするモジュール。"""

import gzip
import hashlib
import json
from collections import defaultdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from importlib.abc import Traversable

# ATT&CK ID (T1059, G0007 など) を持つ external_references の source_name
_ATTACK_SOURCE_NAMES: frozenset[str] = frozenset({"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"})


def is_active(obj: dict[str, Any]) -> bool:
    """廃止(revoked)・非推奨(deprecated)でないオブジェクトかどうか。"""
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def attack_id_of(obj: dict[str, Any]) -> str | None:
    """STIXオブジェクトのATT&CK ID (例: "T1059.001") を返す。無ければNone。"""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in _ATTACK_SOURCE_NAMES and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def attack_url_of(obj: dict[str, Any]) -> str | None:
    """STIXオブジェクトのATT&CKページURLを返す。無ければNone。"""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in _ATTACK_SOURCE_NAMES and ref.get("url"):
            return str(ref["url"])
    return None


class StixBundle:
    """
    gzip圧縮されたSTIXバンドルを読み込み、有効なオブジェクトとrelationshipを索引付けするクラス。

    廃止・非推奨のオブジェクトと、どちらかの端点が無効なrelationshipは除外する。

    Args:
        path (Traversable): {domain}-attack-{version}.json.gz のパス
    """

    def __init__(self, path: "Traversable") -> None:
        with path.open("rb") as f:
            compressed: bytes = f.read()
        # ベクトルDBの再構築判定に使うデータファイルのハッシュ
        self.data_hash: str = hashlib.sha256(compressed).hexdigest()[:16]
        raw: dict[str, Any] = json.loads(gzip.decompress(compressed))
        objects: list[dict[str, Any]] = raw.get("objects", [])

        self.objects_by_id: dict[str, dict[str, Any]] = {}
        self.objects_by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for obj in objects:
            if obj["type"] == "relationship" or not is_active(obj):
                continue
            self.objects_by_id[obj["id"]] = obj
            self.objects_by_type[obj["type"]].append(obj)

        self.relationships: list[dict[str, Any]] = [
            rel
            for rel in objects
            if rel["type"] == "relationship"
            and is_active(rel)
            and rel["source_ref"] in self.objects_by_id
            and rel["target_ref"] in self.objects_by_id
        ]

        # 説明文中の "(Citation: <source_name>)" を解決するための外部参照 (source_name -> 参照)
        self.citations: dict[str, dict[str, Any]] = {}
        for obj in [*self.objects_by_id.values(), *self.relationships]:
            for ref in obj.get("external_references", []):
                name = ref.get("source_name")
                if name and name not in _ATTACK_SOURCE_NAMES and name not in self.citations:
                    self.citations[name] = ref

    def of_type(self, *types: str) -> list[dict[str, Any]]:
        """指定した種類の有効なオブジェクトをATT&CK ID順に返す。ATT&CK IDを持たないものは除外する。"""
        objs = [o for t in types for o in self.objects_by_type.get(t, []) if attack_id_of(o)]
        return sorted(objs, key=lambda o: attack_id_of(o) or "")

    def relationships_of(self, relationship_type: str) -> list[dict[str, Any]]:
        """指定した種類のrelationshipを返す。"""
        return [rel for rel in self.relationships if rel["relationship_type"] == relationship_type]

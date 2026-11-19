import re
from typing import Any

from _security_databases.render import Renderable, body_lines, label, references_list, refs, related_lines

from .reference import AtlasReference
from .technique import AtlasTechnique


class AtlasMitigation(Renderable):
    """
    ATLASの緩和策(mitigation)を表すクラス。

    Args:
        mitigation_id (str): 緩和策のID (例: "AML.M0000")
        name (str): 表示名
        description (str): 説明文(初期化時にリンクなどを清掃)
        tec_lis (list[AtlasTechnique]): この緩和策が対象とするテクニックのリスト
        uuid (str | None): v6形式で付与されるUUID
        references (list[AtlasReference] | None): 外部参照リスト
    """

    def __init__(
        self,
        mitigation_id: str,
        name: str,
        description: str,
        tec_lis: list[AtlasTechnique],
        *,
        uuid: str | None = None,
        references: list[AtlasReference] | None = None,
    ) -> None:
        self.id: str = mitigation_id
        self.name: str = name
        self.description: str = self.clean_description(description)
        self.technique_list: list[AtlasTechnique] = tec_lis
        self.uuid: str | None = uuid
        self.references: list[AtlasReference] | None = references

    def check_technique_by_id(self, technique_id: str) -> bool:
        """
        与えられたテクニックIDがこの緩和策の対象に含まれるかを判定する。

        Args:
            technique_id (str): 判定対象のテクニックID

        Returns:
            bool: 含まれる場合True
        """
        return any(tec.id == technique_id for tec in self.technique_list)

    def clean_description(self, desc: str) -> str:
        """
        descriptionからマークダウンリンクの表示部分のみを残しURL部分を除去する。

        Args:
            desc (str): 元のdescription文字列

        Returns:
            str: 清掃後のdescription文字列
        """
        pattern = r"\[(.*?)\]\(.*?\)"
        replacement = r"\1"
        return re.sub(pattern, replacement, desc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "mitigation",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "techniques": refs(self.technique_list),
            "references": references_list(self.references),
        }

    def _text_lines(self, max_related: int | None) -> list[str]:
        lines = [f"## {label(self)}", "Type: mitigation"]
        lines += body_lines(self.description)
        lines += related_lines("Mitigates techniques", [label(t) for t in self.technique_list], max_related)
        return lines

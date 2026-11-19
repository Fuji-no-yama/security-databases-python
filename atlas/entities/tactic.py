from typing import Any

from _security_databases.render import Renderable, body_lines, label, references_list, refs, related_lines

from .reference import AtlasReference
from .technique import AtlasTechnique


class AtlasTactic(Renderable):
    """
    ATLASのタクティックを表すクラス。

    Args:
        tactic_id (str): タクティックのID (例: "AML.TA0000")
        name (str): 表示名
        description (str): 説明文
        tec_lis (list[AtlasTechnique]): このタクティックに紐づくテクニックのリスト
        uuid (str | None): v6形式で付与されるUUID。v5データからロードした場合はNone
        references (list[AtlasReference] | None): 外部参照リスト
    """

    def __init__(  # noqa: PLR0913
        self,
        tactic_id: str,
        name: str,
        description: str,
        tec_lis: list[AtlasTechnique],
        *,
        uuid: str | None = None,
        references: list[AtlasReference] | None = None,
    ) -> None:
        self.id: str = tactic_id
        self.name: str = name
        self.description: str = description
        self.technique_list: list[AtlasTechnique] = tec_lis
        self.uuid: str | None = uuid
        self.references: list[AtlasReference] | None = references

    def to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "type": "tactic",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "techniques": refs(self.technique_list),
            "references": references_list(self.references),
        }

    def _text_lines(self, max_related: int | None) -> list[str]:
        lines = [f"## {label(self)}", "Type: tactic"]
        lines += body_lines(self.description)
        lines += related_lines("Techniques", [label(t) for t in self.technique_list], max_related)
        return lines

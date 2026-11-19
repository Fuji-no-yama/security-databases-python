import re
from typing import TYPE_CHECKING, Any

from _security_databases.render import (
    Renderable,
    attack_reference_dict,
    body_lines,
    label,
    meta_line,
    ref,
    references_list,
    refs,
    related_lines,
)

from .attack_reference import AtlasAttackReference
from .reference import AtlasReference

if TYPE_CHECKING:
    from .casestudy import AtlasCaseStudy
    from .mitigation import AtlasMitigation
    from .software import AtlasSoftware
    from .tactic import AtlasTactic


class AtlasTechnique(Renderable):
    """
    ATLASのテクニックを表すクラス。

    Args:
        name (str): 表示名
        technique_id (str): テクニックのID (例: "AML.T0000")
        description (str): 説明文(初期化時にリンクなどを清掃)
        have_parent (bool): サブテクニックかどうか
        parent_id (str | None): 親テクニックのID
        tactics (list[AtlasTactic]): 属するタクティックのリスト
        uuid (str | None): v6形式で付与されるUUID
        references (list[AtlasReference] | None): 外部参照リスト
        platforms (list[str] | None): v6で追加されたプラットフォーム一覧
            (例: ["Predictive AI", "Generative AI", "Agentic AI", "Enterprise"])
        maturity (str | None): v6の成熟度 (例: "Demonstrated", "Feasible")
        attack_reference (AtlasAttackReference | None): 対応するATT&CK Techniqueへの参照

    Attributes:
        parent (AtlasTechnique | None): 親テクニック
        subtechnique_list (list[AtlasTechnique]): サブテクニック一覧
        mitigation_list (list[AtlasMitigation]): このテクニックを緩和する緩和策 (mitigates の逆引き)
        casestudy_list (list[AtlasCaseStudy]): このテクニックが使われたケーススタディ (employs の逆引き)
        software_list (list[AtlasSoftware]): このテクニックを実装するソフトウェア (implements の逆引き)。
            6.1.0より前のリリースでは常に空
    """

    def __init__(
        self,
        name: str,
        technique_id: str,
        description: str,
        *,
        have_parent: bool = False,
        parent_id: str | None = None,
        tactics: list["AtlasTactic"],
        uuid: str | None = None,
        references: list[AtlasReference] | None = None,
        platforms: list[str] | None = None,
        maturity: str | None = None,
        attack_reference: AtlasAttackReference | None = None,
    ) -> None:
        self.name: str = name
        self.id: str = technique_id
        self.description: str = self.clean_description(description)
        self.have_parent: bool = have_parent
        self.parent_id: str | None = parent_id
        self.tactics: list[AtlasTactic] = tactics
        self.uuid: str | None = uuid
        self.references: list[AtlasReference] | None = references
        self.platforms: list[str] | None = platforms
        self.maturity: str | None = maturity
        self.attack_reference: AtlasAttackReference | None = attack_reference
        self.parent: AtlasTechnique | None = None
        self.subtechnique_list: list[AtlasTechnique] = []
        self.mitigation_list: list[AtlasMitigation] = []
        self.casestudy_list: list[AtlasCaseStudy] = []
        self.software_list: list[AtlasSoftware] = []

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
            "type": "technique",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "maturity": self.maturity,
            "platforms": self.platforms or [],
            "tactics": refs(self.tactics),
            "parent": ref(self.parent) if self.parent else None,
            "subtechniques": refs(self.subtechnique_list),
            "mitigations": refs(self.mitigation_list),
            "software": refs(self.software_list),
            "case_studies": refs(self.casestudy_list),
            "attack_reference": attack_reference_dict(self.attack_reference),
            "references": references_list(self.references),
        }

    def _text_lines(self, max_related: int | None) -> list[str]:
        meta = meta_line(
            "Type: technique",
            f"Maturity: {self.maturity}" if self.maturity else None,
            f"Platforms: {', '.join(self.platforms)}" if self.platforms else None,
            f"ATT&CK: {self.attack_reference.id}" if self.attack_reference else None,
        )
        lines = [f"## {label(self)}", meta]
        if self.tactics:
            lines.append(f"Tactics: {', '.join(label(t) for t in self.tactics)}")
        if self.parent:
            lines.append(f"Parent technique: {label(self.parent)}")
        lines += body_lines(self.description)
        lines += related_lines("Sub-techniques", [label(t) for t in self.subtechnique_list], max_related)
        lines += related_lines("Mitigated by", [label(m) for m in self.mitigation_list], max_related)
        lines += related_lines(
            "Implemented by software",
            [f"{label(s)} ({s.software_type})" for s in self.software_list],
            max_related,
        )
        lines += related_lines("Observed in case studies", [label(c) for c in self.casestudy_list], max_related)
        return lines

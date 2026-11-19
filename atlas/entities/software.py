import re
from typing import TYPE_CHECKING, Any, Literal

from _security_databases.render import (
    Renderable,
    attack_reference_dict,
    body_lines,
    label,
    meta_line,
    references_list,
    refs,
    related_lines,
)

from .attack_reference import AtlasAttackReference
from .reference import AtlasReference

if TYPE_CHECKING:
    from .casestudy import AtlasCaseStudy
    from .entity import AtlasEntity
    from .technique import AtlasTechnique

SoftwareType = Literal["Malware", "Tool"]


class AtlasSoftware(Renderable):
    """
    ATLASのソフトウェア(format-version 6.1.0で追加)を表すクラス。

    Args:
        software_id (str): ソフトウェアID (例: "AML.S0015")
        name (str): 表示名
        description (str): 説明文(初期化時にマークダウンリンクを清掃)
        software_type (SoftwareType): "Malware" または "Tool"
        software_categories (list[str]): カテゴリ一覧
            (program / library / model / service / ai-agent / ai-agent-framework / ai-agent-integration / prompt-package)
        aliases (list[str]): 別名一覧
        attack_reference (AtlasAttackReference | None): 対応するATT&CK Softwareへの参照
        uuid (str | None): UUID
        references (list[AtlasReference] | None): 外部参照リスト
        created_date (str | None): 作成日 (例: "2026-10-28")
        modified_date (str | None): 更新日

    Attributes:
        technique_list (list[AtlasTechnique]): このソフトウェアが実装するテクニック (implements)
        entity_list (list[AtlasEntity]): このソフトウェアを使用するエンティティ (Entity → Software uses の逆引き)
        casestudy_list (list[AtlasCaseStudy]): このソフトウェアが使用されたケーススタディ (CaseStudy → Software uses の逆引き)
    """

    def __init__(  # noqa: PLR0913
        self,
        software_id: str,
        name: str,
        description: str,
        software_type: SoftwareType,
        *,
        software_categories: list[str] | None = None,
        aliases: list[str] | None = None,
        attack_reference: AtlasAttackReference | None = None,
        uuid: str | None = None,
        references: list[AtlasReference] | None = None,
        created_date: str | None = None,
        modified_date: str | None = None,
    ) -> None:
        self.id: str = software_id
        self.name: str = name
        self.description: str = re.sub(r"\[(.*?)\]\(.*?\)", r"\1", description)
        self.software_type: SoftwareType = software_type
        self.software_categories: list[str] = software_categories or []
        self.aliases: list[str] = aliases or []
        self.attack_reference: AtlasAttackReference | None = attack_reference
        self.uuid: str | None = uuid
        self.references: list[AtlasReference] | None = references
        self.created_date: str | None = created_date
        self.modified_date: str | None = modified_date
        self.technique_list: list[AtlasTechnique] = []
        self.entity_list: list[AtlasEntity] = []
        self.casestudy_list: list[AtlasCaseStudy] = []

    def to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "type": "software",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "software_type": self.software_type,
            "software_categories": self.software_categories,
            "aliases": self.aliases,
            "techniques": refs(self.technique_list),
            "entities": refs(self.entity_list),
            "case_studies": refs(self.casestudy_list),
            "attack_reference": attack_reference_dict(self.attack_reference),
            "references": references_list(self.references),
        }

    def _text_lines(self, max_related: int | None) -> list[str]:
        meta = meta_line(
            f"Type: software ({self.software_type})",
            f"Categories: {', '.join(self.software_categories)}" if self.software_categories else None,
            f"ATT&CK: {self.attack_reference.id}" if self.attack_reference else None,
        )
        lines = [f"## {label(self)}", meta]
        if self.aliases:
            lines.append(f"Aliases: {', '.join(self.aliases)}")
        lines += body_lines(self.description)
        lines += related_lines("Implements techniques", [label(t) for t in self.technique_list], max_related)
        lines += related_lines("Used by entities", [label(e) for e in self.entity_list], max_related)
        lines += related_lines("Used in case studies", [label(c) for c in self.casestudy_list], max_related)
        return lines

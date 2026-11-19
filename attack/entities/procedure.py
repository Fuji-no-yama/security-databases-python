from typing import TYPE_CHECKING, Any

from _security_databases.render import Renderable, meta_line, ref

from ._text import description_lines, reference_dicts, technique_label, technique_ref
from .reference import AttackExternalReference, AttackInternalReference

if TYPE_CHECKING:
    from .campaign import AttackCampaign
    from .group import AttackGroup
    from .software import AttackSoftware
    from .technique import AttackTechnique


class AttackProcedure(Renderable):
    def __init__(
        self,
        original_id: str,
        parent_id: str,
        parent_name: str,
        parent_type: str,
        technique_id: str,
        description: str,
        domain: str,
        reference_list: list[AttackExternalReference | AttackInternalReference],
        *,
        stix_id: str | None = None,
        raw_description: str | None = None,
    ) -> None:
        self.original_id: str = original_id
        self.parent_id: str = parent_id
        self.parent_name: str = parent_name
        self.parent_type: str = parent_type
        self.technique_id: str = technique_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
        self.reference_list: list[AttackExternalReference | AttackInternalReference] = reference_list
        self.stix_id: str | None = stix_id  # 元になったuses relationshipのSTIX ID
        self.raw_description: str | None = raw_description  # STIXの説明文 (引用を整形する前の原文)
        self.parent: AttackGroup | AttackSoftware | AttackCampaign | None = None
        self.technique: AttackTechnique | None = None

    def get_description_include_references(self) -> str:
        """参考資料を含む説明文を取得する"""
        desc = self.description
        if self.reference_list:
            desc += "\n\nReference:\n"
            for i, ref in enumerate(self.reference_list):
                if isinstance(ref, AttackExternalReference):
                    desc += f'- [{i}] "{ref.name}" {ref.url}\n'
                elif isinstance(ref, AttackInternalReference):
                    if ref.id == self.parent_id:
                        desc += f'- [{i}] "{self.parent_name}" {ref.url}\n'
                    else:
                        desc += f"- [{i}] {ref.id} {ref.url}\n"
        return desc

    @property
    def id(self) -> str:
        """プロシージャID (original_id と同じ。例: "P0001")。バージョンごとに採番されるため永続的なIDではない。"""
        return self.original_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "procedure",
            "id": self.original_id,
            "stix_id": self.stix_id,
            "domain": self.domain,
            "parent": ref(self.parent) if self.parent else {"id": self.parent_id, "name": self.parent_name},
            "parent_type": self.parent_type,
            "technique": technique_ref(self.technique) if self.technique else {"id": self.technique_id, "name": None},
            "description": self.description,
            "references": reference_dicts(self.reference_list),
        }

    def _text_lines(self, max_related: int | None) -> list[str]:  # noqa: ARG002
        technique = technique_label(self.technique) if self.technique else self.technique_id
        lines = [
            f"## {self.original_id} {self.parent_name} ({self.parent_type}) uses {technique}",
            meta_line("Type: procedure", f"Domain: {self.domain}"),
        ]
        lines += description_lines(self.raw_description, self.description)
        return lines

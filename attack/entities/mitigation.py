from typing import TYPE_CHECKING, Any

from _security_databases.render import Renderable, label, meta_line, related_lines

from ._text import description_lines, reference_dicts, technique_label, technique_ref
from .reference import AttackExternalReference, AttackInternalReference

if TYPE_CHECKING:
    from .technique import AttackTechnique


class AttackAbstractMitigation(Renderable):  # 1つの抽象緩和策を表すクラス(具体緩和策を保有)
    def __init__(
        self,
        name: str,
        mitigation_id: str,
        description: str,
        domain: str,
        concrete_mitigation_list: list["AttackConcreteMitigation"],
        reference_list: list[AttackExternalReference | AttackInternalReference],
        *,
        stix_id: str | None = None,
        raw_description: str | None = None,
    ) -> None:
        self.name: str = name
        self.id: str = mitigation_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
        self.concrete_mitigation_list: list[AttackConcreteMitigation] = concrete_mitigation_list
        self.reference_list: list[AttackExternalReference | AttackInternalReference] = reference_list
        self.stix_id: str | None = stix_id
        self.raw_description: str | None = raw_description  # STIXの説明文 (引用を整形する前の原文)

    def get_description_include_references(self) -> str:
        """参考資料を含む説明文を取得する"""
        desc = self.description
        if self.reference_list:
            desc += "\n\nReference:\n"
            for i, ref in enumerate(self.reference_list):
                if isinstance(ref, AttackExternalReference):
                    desc += f'- [{i}] "{ref.name}" {ref.url}\n'
                elif isinstance(ref, AttackInternalReference):
                    if ref.id == self.id:
                        desc += f'- [{i}] "{self.name}" {ref.url}\n'
                    else:
                        desc += f"- [{i}] {ref.id} {ref.url}\n"
        return desc

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "mitigation",
            "id": self.id,
            "name": self.name,
            "domain": self.domain,
            "description": self.description,
            "techniques": [{**technique_ref(c.technique), "description": c.description} for c in self.concrete_mitigation_list if c.technique],
            "references": reference_dicts(self.reference_list),
        }

    def _text_lines(self, max_related: int | None) -> list[str]:
        lines = [f"## {label(self)}", meta_line("Type: mitigation", f"Domain: {self.domain}")]
        lines += description_lines(self.raw_description, self.description)
        techniques = [technique_label(c.technique) for c in self.concrete_mitigation_list if c.technique]
        lines += related_lines("Mitigates techniques", techniques, max_related)
        return lines


class AttackConcreteMitigation:  # 1つの具体緩和策を表すクラス
    def __init__(
        self,
        abstract_mitigation_id: str,
        abstract_mitigation_name: str,
        technique_id: str,
        description: str,
        domain: str,
        reference_list: list[AttackExternalReference | AttackInternalReference],
        *,
        stix_id: str | None = None,
        raw_description: str | None = None,
    ) -> None:
        self.abstract_mitigation_id: str = abstract_mitigation_id
        self.abstract_mitigation_name: str = abstract_mitigation_name
        self.technique_id: str = technique_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
        self.reference_list: list[AttackExternalReference | AttackInternalReference] = reference_list
        self.stix_id: str | None = stix_id  # 元になったmitigates relationshipのSTIX ID
        self.raw_description: str | None = raw_description  # STIXの説明文 (引用を整形する前の原文)
        self.mitigation: AttackAbstractMitigation | None = None
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
                    if ref.id == self.abstract_mitigation_id:
                        desc += f'- [{i}] "{self.abstract_mitigation_name}" {ref.url}\n'
                    else:
                        desc += f"- [{i}] {ref.id} {ref.url}\n"
        return desc

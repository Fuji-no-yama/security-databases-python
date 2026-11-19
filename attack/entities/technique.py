from typing import TYPE_CHECKING, Any

from _security_databases.render import Renderable, label, meta_line, ref, refs, related_lines

from ._text import description_lines, reference_dicts, technique_label, technique_ref, unique
from .reference import AttackExternalReference, AttackInternalReference

if TYPE_CHECKING:
    from .campaign import AttackProcedure
    from .mitigation import AttackConcreteMitigation
    from .tactic import AttackTactic


class AttackTechnique(Renderable):
    def __init__(
        self,
        name: str,
        technique_id: str,
        domain: str,
        description: str,
        *,
        mitigation_list: list["AttackConcreteMitigation"] | None = None,
        procedure_list: list["AttackProcedure"] | None = None,
        have_parent: bool = False,
        parent_id: str | None = None,
        tactics: list["AttackTactic"],
        reference_list: list[AttackExternalReference | AttackInternalReference],
        stix_id: str | None = None,
        raw_description: str | None = None,
        platforms: list[str] | None = None,
        url: str | None = None,
    ) -> None:
        self.name: str = name
        self.id: str = technique_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
        self.mitigation_list: list[AttackConcreteMitigation] = mitigation_list if mitigation_list is not None else []
        self.procedure_list: list[AttackProcedure] = procedure_list if procedure_list is not None else []
        self.have_parent: bool = have_parent
        self.parent_id: str | None = parent_id
        self.tactics: list[AttackTactic] = tactics
        self.reference_list: list[AttackExternalReference | AttackInternalReference] = reference_list
        self.stix_id: str | None = stix_id
        self.raw_description: str | None = raw_description  # STIXの説明文 (引用を整形する前の原文)
        self.platforms: list[str] = platforms or []
        self.url: str | None = url
        self.parent: AttackTechnique | None = None
        self.subtechnique_list: list[AttackTechnique] = []

    @property
    def full_name(self) -> str:
        """
        親テクニック名を含む表示名を返す (例: "Abuse Elevation Control Mechanism: Bypass User Account Control")。

        STIXのnameはサブテクニック単体の名前のため、文脈が必要な場合はこちらを使う。
        親テクニックでは name と同じ。
        """
        return f"{self.parent.name}: {self.name}" if self.parent is not None else self.name

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
            "type": "technique",
            "id": self.id,
            "name": self.name,
            "full_name": self.full_name,
            "domain": self.domain,
            "description": self.description,
            "platforms": self.platforms,
            "url": self.url,
            "tactics": refs(self.tactics),
            "parent": technique_ref(self.parent) if self.parent else None,
            "subtechniques": [technique_ref(t) for t in self.subtechnique_list],
            "mitigations": refs(unique([m.mitigation for m in self.mitigation_list if m.mitigation])),
            "procedures": [
                {"id": p.original_id, "parent": ref(p.parent) if p.parent else None, "parent_type": p.parent_type} for p in self.procedure_list
            ],
            "references": reference_dicts(self.reference_list),
        }

    def _text_lines(self, max_related: int | None) -> list[str]:
        meta = meta_line(
            "Type: technique",
            f"Domain: {self.domain}",
            f"Platforms: {', '.join(self.platforms)}" if self.platforms else None,
        )
        lines = [f"## {technique_label(self)}", meta]
        if self.tactics:
            lines.append(f"Tactics: {', '.join(label(t) for t in self.tactics)}")
        if self.parent:
            lines.append(f"Parent technique: {technique_label(self.parent)}")
        lines += description_lines(self.raw_description, self.description)
        lines += related_lines("Sub-techniques", [technique_label(t) for t in self.subtechnique_list], max_related)
        mitigations = unique([m.mitigation for m in self.mitigation_list if m.mitigation])
        lines += related_lines("Mitigations", [label(m) for m in mitigations], max_related)
        procedures = [f"{label(p.parent)} ({p.parent_type})" for p in self.procedure_list if p.parent]
        lines += related_lines("Procedure examples", procedures, max_related)
        return lines

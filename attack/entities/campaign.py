from typing import TYPE_CHECKING, Any

from _security_databases.render import Renderable, label, meta_line, refs, related_lines

from ._text import description_lines, reference_dicts, technique_label, technique_ref, unique
from .reference import AttackExternalReference, AttackInternalReference

if TYPE_CHECKING:
    from .group import AttackGroup
    from .procedure import AttackProcedure
    from .software import AttackSoftware
    from .technique import AttackTechnique


class AttackCampaign(Renderable):
    def __init__(  # noqa: PLR0913
        self,
        name: str,
        campaign_id: str,
        description: str,
        domain: str,
        procedure_list: list["AttackProcedure"],
        reference_list: list[AttackExternalReference | AttackInternalReference],
        *,
        stix_id: str | None = None,
        raw_description: str | None = None,
        aliases: list[str] | None = None,
        url: str | None = None,
        first_seen: str | None = None,
        last_seen: str | None = None,
    ) -> None:
        self.name: str = name
        self.id: str = campaign_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
        self.procedure_list: list[AttackProcedure] = procedure_list
        self.reference_list: list[AttackExternalReference | AttackInternalReference] = reference_list
        self.stix_id: str | None = stix_id
        self.raw_description: str | None = raw_description  # STIXの説明文 (引用を整形する前の原文)
        self.aliases: list[str] = aliases or []
        self.url: str | None = url
        self.first_seen: str | None = first_seen  # 例: "2015-12-01T05:00:00.000Z"
        self.last_seen: str | None = last_seen
        self.group_list: list[AttackGroup] = []  # 帰属先グループ (attributed-to)
        self.software_list: list[AttackSoftware] = []  # このキャンペーンで使用されたソフトウェア (uses)

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

    def to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "type": "campaign",
            "id": self.id,
            "name": self.name,
            "domain": self.domain,
            "aliases": self.aliases,
            "description": self.description,
            "url": self.url,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "groups": refs(self.group_list),
            "software": refs(self.software_list),
            "techniques": [technique_ref(t) for t in self._techniques()],
            "references": reference_dicts(self.reference_list),
        }

    def _techniques(self) -> list["AttackTechnique"]:
        return unique([p.technique for p in self.procedure_list if p.technique])

    def _text_lines(self, max_related: int | None) -> list[str]:
        meta = meta_line(
            "Type: campaign",
            f"Domain: {self.domain}",
            f"First seen: {self.first_seen[:10]}" if self.first_seen else None,
            f"Last seen: {self.last_seen[:10]}" if self.last_seen else None,
        )
        lines = [f"## {label(self)}", meta]
        if self.aliases:
            lines.append(f"Aliases: {', '.join(self.aliases)}")
        lines += description_lines(self.raw_description, self.description)
        lines += related_lines("Attributed to groups", [label(g) for g in self.group_list], max_related)
        lines += related_lines("Software used", [label(s) for s in self.software_list], max_related)
        lines += related_lines("Techniques used", [technique_label(t) for t in self._techniques()], max_related)
        return lines

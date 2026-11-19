from typing import Any

from _security_databases.render import Renderable, label, meta_line, related_lines

from ._text import description_lines, technique_label, technique_ref
from .technique import AttackTechnique


class AttackTactic(Renderable):
    def __init__(
        self,
        tactic_id: str,
        name: str,
        domain: str,
        description: str,
        technique_list: list[AttackTechnique],
        *,
        shortname: str | None = None,
        stix_id: str | None = None,
    ) -> None:
        self.id: str = tactic_id
        self.name: str = name
        self.domain: str = domain
        self.description: str = description
        self.technique_list: list[AttackTechnique] = technique_list  # list[AttackTechnique]の形を保持したリスト
        self.shortname: str | None = shortname  # STIXのx_mitre_shortname (例: "initial-access")
        self.stix_id: str | None = stix_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "tactic",
            "id": self.id,
            "name": self.name,
            "domain": self.domain,
            "description": self.description,
            "techniques": [technique_ref(t) for t in self.technique_list],
        }

    def _text_lines(self, max_related: int | None) -> list[str]:
        lines = [f"## {label(self)}", meta_line("Type: tactic", f"Domain: {self.domain}")]
        lines += description_lines(self.description)
        lines += related_lines("Techniques", [technique_label(t) for t in self.technique_list], max_related)
        return lines

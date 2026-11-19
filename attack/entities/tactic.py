
from .technique import AttackTechnique


class AttackTactic:
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

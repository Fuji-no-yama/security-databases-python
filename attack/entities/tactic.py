
from .technique import AttackTechnique


class AttackTactic:
    def __init__(
        self,
        tactic_id: str,
        name: str,
        domain: str,
        description: str,
        technique_list: list[AttackTechnique],
    ) -> None:
        self.id: str = tactic_id
        self.name: str = name
        self.domain: str = domain
        self.description: str = description
        self.technique_list: list[AttackTechnique] = technique_list  # list[AttackTechnique]の形を保持したリスト

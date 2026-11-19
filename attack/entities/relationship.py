from typing import Any


class AttackRelationship:
    """
    STIXのrelationship (2つのATT&CKオブジェクトを結ぶ関係) を表すクラス。

    主な種別:
        uses: Group / Software / Campaign → Technique、Group / Campaign → Software
        mitigates: Mitigation → Technique
        subtechnique-of: Sub-technique → Technique
        attributed-to: Campaign → Group
        detects: Detection Strategy → Technique
        targets: Technique → Asset (ICS)

    Args:
        source_id (str): 起点のATT&CK ID (例: "G0007")
        target_id (str): 対象のATT&CK ID (例: "T1059.001")
        type (str): 関係種別 (STIXの relationship_type)
        description (str | None): 関係の説明文 (STIXの原文)
        stix_id (str | None): relationshipのSTIX ID
        source_type (str | None): 起点のSTIX type (例: "intrusion-set")
        target_type (str | None): 対象のSTIX type (例: "attack-pattern")
        raw (dict[str, Any] | None): 元のSTIX relationship
    """

    def __init__(
        self,
        source_id: str,
        target_id: str,
        type: str,  # noqa: A002
        *,
        description: str | None = None,
        stix_id: str | None = None,
        source_type: str | None = None,
        target_type: str | None = None,
        raw: dict[str, Any] | None = None,
    ) -> None:
        self.source_id: str = source_id
        self.target_id: str = target_id
        self.type: str = type
        self.description: str | None = description
        self.stix_id: str | None = stix_id
        self.source_type: str | None = source_type
        self.target_type: str | None = target_type
        self.raw: dict[str, Any] = raw if raw is not None else {}

import re
from typing import TYPE_CHECKING, Literal

from .attack_reference import AtlasAttackReference
from .reference import AtlasReference

if TYPE_CHECKING:
    from .casestudy import AtlasCaseStudy
    from .software import AtlasSoftware
    from .technique import AtlasTechnique

EntityType = Literal["Activity Cluster", "Organization", "Team", "Individual"]


class AtlasAssociatedEntity:
    """
    エンティティに関連付けられた別名・関連組織を表すクラス。

    Args:
        name (str): 名前 (例: "Fancy Bear")
        description (str | None): 説明。無ければNone
    """

    def __init__(self, name: str, description: str | None = None) -> None:
        self.name: str = name
        self.description: str | None = description


class AtlasEntity:
    """
    ATLASのエンティティ(format-version 6.1.0で追加)を表すクラス。

    攻撃者グループ、組織、チーム、個人など、ケーススタディの活動主体を表す。

    Args:
        entity_id (str): エンティティID (例: "AML.E0018")
        name (str): 表示名
        description (str): 説明文(初期化時にマークダウンリンクを清掃)
        entity_type (EntityType): "Activity Cluster" / "Organization" / "Team" / "Individual"
        associated_entities (list[AtlasAssociatedEntity] | None): 別名・関連組織の一覧
        attack_reference (AtlasAttackReference | None): 対応するATT&CK Groupへの参照
        uuid (str | None): UUID
        references (list[AtlasReference] | None): 外部参照リスト
        created_date (str | None): 作成日 (例: "2026-10-28")
        modified_date (str | None): 更新日

    Attributes:
        technique_list (list[AtlasTechnique]): このエンティティが使用するテクニック (uses)
        software_list (list[AtlasSoftware]): このエンティティが使用するソフトウェア (uses)
        casestudy_list (list[AtlasCaseStudy]): このエンティティに帰属するケーススタディ (attributed-to の逆引き)
    """

    def __init__(  # noqa: PLR0913
        self,
        entity_id: str,
        name: str,
        description: str,
        entity_type: EntityType,
        *,
        associated_entities: list[AtlasAssociatedEntity] | None = None,
        attack_reference: AtlasAttackReference | None = None,
        uuid: str | None = None,
        references: list[AtlasReference] | None = None,
        created_date: str | None = None,
        modified_date: str | None = None,
    ) -> None:
        self.id: str = entity_id
        self.name: str = name
        self.description: str = re.sub(r"\[(.*?)\]\(.*?\)", r"\1", description)
        self.entity_type: EntityType = entity_type
        self.associated_entities: list[AtlasAssociatedEntity] = associated_entities or []
        self.attack_reference: AtlasAttackReference | None = attack_reference
        self.uuid: str | None = uuid
        self.references: list[AtlasReference] | None = references
        self.created_date: str | None = created_date
        self.modified_date: str | None = modified_date
        self.technique_list: list[AtlasTechnique] = []
        self.software_list: list[AtlasSoftware] = []
        self.casestudy_list: list[AtlasCaseStudy] = []

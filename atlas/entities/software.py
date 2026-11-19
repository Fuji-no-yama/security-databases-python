import re
from typing import TYPE_CHECKING, Literal

from .attack_reference import AtlasAttackReference
from .reference import AtlasReference

if TYPE_CHECKING:
    from .technique import AtlasTechnique

SoftwareType = Literal["Malware", "Tool"]


class AtlasSoftware:
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

from typing import TYPE_CHECKING, Literal

from .reference import AtlasReference
from .relationship import ActivityPurpose
from .tactic import AtlasTactic
from .technique import AtlasTechnique

if TYPE_CHECKING:
    from .entity import AtlasEntity
    from .software import AtlasSoftware

DateGranularity = Literal["Year", "Month", "Day"]


class AtlasCaseStudyAttribution:
    """
    ケーススタディの帰属先(attributed-to)を表すクラス。

    活動の目的はエンティティ自体ではなく個々の活動に付くため、エンティティと目的の組で保持する。

    Args:
        entity (AtlasEntity): 帰属先エンティティ
        activity_purpose (ActivityPurpose | None): 活動の目的
            ("Adversarial Operation" / "Security Evaluation" / "Unintended Consequence")
        description (str | None): 帰属に関する補足説明
    """

    def __init__(
        self,
        entity: "AtlasEntity",
        activity_purpose: ActivityPurpose | None = None,
        description: str | None = None,
    ) -> None:
        self.entity: AtlasEntity = entity
        self.activity_purpose: ActivityPurpose | None = activity_purpose
        self.description: str | None = description


class AtlasCaseStudyStep:
    """
    ケーススタディの1ステップ(procedure要素)を表すクラス。

    Args:
        casestudy_step_id (str): 親ID+step-idを結合したユニークID (例: "AML.CS0000.S00")
        tactic (AtlasTactic): このステップに対応するタクティック
        technique (AtlasTechnique): このステップに対応するテクニック
        description (str): 説明文
        parent_id (str): 親ケーススタディのID (例: "AML.CS0000")
        step_id (str | None): v6のstep-id(例: "S00")、旧形式からロード時はNone
        leads_to (list[str] | None): 次に遷移し得るstep-idのリスト。無ければNone
    """

    def __init__(  # noqa: PLR0913
        self,
        casestudy_step_id: str,
        tactic: AtlasTactic,
        technique: AtlasTechnique,
        description: str,
        parent_id: str,
        *,
        step_id: str | None = None,
        leads_to: list[str] | None = None,
    ) -> None:
        self.id: str = casestudy_step_id
        self.tactic: AtlasTactic = tactic
        self.technique: AtlasTechnique = technique
        self.description: str = description
        self.parent_id: str = parent_id
        self.step_id: str | None = step_id
        self.leads_to: list[str] | None = leads_to


class AtlasCaseStudy:
    """
    ATLASのケーススタディを表すクラス。

    Args:
        casestudy_id (str): ケーススタディID (例: "AML.CS0000")
        name (str): 表示名
        summary (str): 概要説明
        step_list (list[AtlasCaseStudyStep]): 手順ステップリスト
        target (str): 対象システム
        actor (str): 攻撃者(自由記述)。データに無い場合は空文字列。
            format-version 6.1.0以降は任意項目となり、帰属先は attributions で表される
        casestudy_type (Literal["Exercise", "Incident"]): v6のcase-study type
        reference_title_list (list[str] | None): 参照タイトル一覧(下位互換用)
        reference_url_list (list[str] | None): 参照URL一覧(下位互換用)
        uuid (str | None): v6形式で付与されるUUID
        references (list[AtlasReference] | None): 構造化された参照リスト
        reporter (str | None): 報告者(自由記述)。無ければNone
        start_date (str | None): 開始日 (例: "2025-06-03")。6.1.0より前のデータでは
            同義の旧項目 date を読み替えた値
        start_date_granularity (DateGranularity | None): start_date の粒度。
            6.1.0より前のデータでは旧項目 date-granularity を読み替えた値
        end_date (str | None): 終了日。6.1.0以降でNoneの場合は継続中を表す。
            6.1.0より前のデータには存在しないため常にNone
        end_date_granularity (DateGranularity | None): end_date の粒度

    Attributes:
        attributions (list[AtlasCaseStudyAttribution]): 帰属先エンティティと活動目的 (attributed-to)
        reported_by (list[AtlasEntity]): 報告者エンティティ (reported-by)
        software_list (list[AtlasSoftware]): このケーススタディで使用されたソフトウェア (uses)
        いずれも6.1.0より前のリリースでは常に空
    """

    def __init__(  # noqa: PLR0913
        self,
        casestudy_id: str,
        name: str,
        summary: str,
        step_list: list[AtlasCaseStudyStep],
        target: str,
        actor: str,
        casestudy_type: Literal["Exercise", "Incident"],
        *,
        reference_title_list: list[str] | None = None,
        reference_url_list: list[str] | None = None,
        uuid: str | None = None,
        references: list[AtlasReference] | None = None,
        reporter: str | None = None,
        start_date: str | None = None,
        start_date_granularity: DateGranularity | None = None,
        end_date: str | None = None,
        end_date_granularity: DateGranularity | None = None,
    ) -> None:
        self.id: str = casestudy_id
        self.name: str = name
        self.summary: str = summary
        self.procedure: list[AtlasCaseStudyStep] = step_list
        self.target: str = target
        self.actor: str = actor
        self.type: Literal["Exercise", "Incident"] = casestudy_type
        self.reference_title_list: list[str] | None = reference_title_list
        self.reference_url_list: list[str] | None = reference_url_list
        self.uuid: str | None = uuid
        self.references: list[AtlasReference] | None = references
        self.reporter: str | None = reporter
        self.start_date: str | None = start_date
        self.start_date_granularity: DateGranularity | None = start_date_granularity
        self.end_date: str | None = end_date
        self.end_date_granularity: DateGranularity | None = end_date_granularity
        self.attributions: list[AtlasCaseStudyAttribution] = []
        self.reported_by: list[AtlasEntity] = []
        self.software_list: list[AtlasSoftware] = []

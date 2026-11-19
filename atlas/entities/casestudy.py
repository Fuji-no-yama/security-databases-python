from typing import TYPE_CHECKING, Any, Literal

from _security_databases.render import (
    Renderable,
    body_lines,
    label,
    meta_line,
    ref,
    references_list,
    refs,
    related_lines,
)

from .reference import AtlasReference
from .relationship import ActivityPurpose
from .tactic import AtlasTactic
from .technique import AtlasTechnique

if TYPE_CHECKING:
    from .entity import AtlasEntity
    from .software import AtlasSoftware

DateGranularity = Literal["Year", "Month", "Day"]

_DATE_LENGTH: dict[str, int] = {"Year": 4, "Month": 7, "Day": 10}


def _format_date(date: str | None, granularity: str | None) -> str | None:
    """日付を粒度に合わせて切り詰める (例: "2025-06-03", "Month" -> "2025-06")。"""
    if not date:
        return None
    return date[: _DATE_LENGTH.get(granularity or "", len(date))]


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


class AtlasCaseStudyStep(Renderable):
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

    Attributes:
        casestudy (AtlasCaseStudy | None): 親ケーススタディ
    """

    def __init__(
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
        self.casestudy: AtlasCaseStudy | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "case-study-step",
            "id": self.id,
            "step_id": self.step_id,
            "case_study": ref(self.casestudy) if self.casestudy else {"id": self.parent_id, "name": None},
            "tactic": ref(self.tactic),
            "technique": ref(self.technique),
            "description": self.description,
            "leads_to": self.leads_to or [],
        }

    def _text_lines(self, max_related: int | None) -> list[str]:  # noqa: ARG002
        lines = [
            f"## {self.id} [{self.tactic.name}] {label(self.technique)}",
            "Type: case-study-step",
            f"Case study: {label(self.casestudy) if self.casestudy else self.parent_id}",
        ]
        if self.leads_to:
            lines.append(f"Leads to: {', '.join(self.leads_to)}")
        lines += body_lines(self.description)
        return lines


class AtlasCaseStudy(Renderable):
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

    def __init__(
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

    def _period_text(self) -> str | None:
        start = _format_date(self.start_date, self.start_date_granularity)
        end = _format_date(self.end_date, self.end_date_granularity)
        if start is None:
            return None
        if end is None:
            return f"Start: {start} ({self.start_date_granularity})"
        if end == start:
            return f"Period: {start} ({self.start_date_granularity})"
        return f"Period: {start} to {end}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "case-study",
            "id": self.id,
            "name": self.name,
            "case_study_type": self.type,
            "summary": self.summary,
            "target": self.target,
            "actor": self.actor,
            "reporter": self.reporter,
            "start_date": self.start_date,
            "start_date_granularity": self.start_date_granularity,
            "end_date": self.end_date,
            "end_date_granularity": self.end_date_granularity,
            "attributions": [
                {"entity": ref(a.entity), "activity_purpose": a.activity_purpose, "description": a.description} for a in self.attributions
            ],
            "reported_by": refs(self.reported_by),
            "software": refs(self.software_list),
            "procedure": [
                {
                    "step_id": s.step_id,
                    "tactic": ref(s.tactic),
                    "technique": ref(s.technique),
                    "description": s.description,
                    "leads_to": s.leads_to or [],
                }
                for s in self.procedure
            ],
            "references": references_list(self.references),
        }

    def _text_lines(self, max_related: int | None) -> list[str]:
        meta = meta_line(
            f"Type: case-study ({self.type})",
            self._period_text(),
            f"Target: {self.target}" if self.target else None,
        )
        lines = [f"## {label(self)}", meta]
        if self.attributions:
            attributed = [f"{label(a.entity)} [{a.activity_purpose}]" if a.activity_purpose else label(a.entity) for a in self.attributions]
            lines.append(f"Attributed to: {', '.join(attributed)}")
        if self.actor:
            lines.append(f"Actor: {self.actor}")
        if self.reported_by:
            lines.append(f"Reported by: {', '.join(label(e) for e in self.reported_by)}")
        if self.reporter:
            lines.append(f"Reporter: {self.reporter}")
        lines += body_lines(self.summary)
        lines += related_lines("Uses software", [label(s) for s in self.software_list], max_related)
        steps = [
            f"{s.step_id} [{s.tactic.name}] {label(s.technique)}" + (f" -> {', '.join(s.leads_to)}" if s.leads_to else "") for s in self.procedure
        ]
        lines += related_lines("Procedure", steps, max_related)
        return lines

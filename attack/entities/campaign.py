from typing import TYPE_CHECKING

from .reference import AttackExternalReference, AttackInternalReference

if TYPE_CHECKING:
    from .group import AttackGroup
    from .procedure import AttackProcedure
    from .software import AttackSoftware


class AttackCampaign:
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

from typing import TYPE_CHECKING

from .reference import AttackExternalReference, AttackInternalReference

if TYPE_CHECKING:
    from .campaign import AttackProcedure
    from .mitigation import AttackConcreteMitigation
    from .tactic import AttackTactic


class AttackTechnique:
    def __init__(  # noqa: PLR0913 (引数総数警告)
        self,
        name: str,
        technique_id: str,
        domain: str,
        description: str,
        *,
        mitigation_list: list["AttackConcreteMitigation"] | None = None,
        procedure_list: list["AttackProcedure"] | None = None,
        have_parent: bool = False,
        parent_id: str | None = None,
        tactics: list["AttackTactic"],
        reference_list: list[AttackExternalReference | AttackInternalReference],
        stix_id: str | None = None,
        platforms: list[str] | None = None,
        url: str | None = None,
    ) -> None:
        self.name: str = name
        self.id: str = technique_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
        self.mitigation_list: list[AttackConcreteMitigation] = mitigation_list if mitigation_list is not None else []
        self.procedure_list: list[AttackProcedure] = procedure_list if procedure_list is not None else []
        self.have_parent: bool = have_parent
        self.parent_id: str | None = parent_id
        self.tactics: list[AttackTactic] = tactics
        self.reference_list: list[AttackExternalReference | AttackInternalReference] = reference_list
        self.stix_id: str | None = stix_id
        self.platforms: list[str] = platforms or []
        self.url: str | None = url
        self.parent: AttackTechnique | None = None
        self.subtechnique_list: list[AttackTechnique] = []

    @property
    def full_name(self) -> str:
        """
        親テクニック名を含む表示名を返す (例: "Abuse Elevation Control Mechanism: Bypass User Account Control")。

        STIXのnameはサブテクニック単体の名前のため、文脈が必要な場合はこちらを使う。
        親テクニックでは name と同じ。
        """
        return f"{self.parent.name}: {self.name}" if self.parent is not None else self.name

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

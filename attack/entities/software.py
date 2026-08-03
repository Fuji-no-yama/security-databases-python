from typing import TYPE_CHECKING

from .reference import AttackExternalReference, AttackInternalReference

if TYPE_CHECKING:
    from .procedure import AttackProcedure


class AttackSoftware:
    def __init__(
        self,
        name: str,
        software_id: str,
        description: str,
        domain: str,
        procedure_list: list["AttackProcedure"],
        reference_list: list[AttackExternalReference | AttackInternalReference],
    ) -> None:
        self.name: str = name
        self.id: str = software_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
        self.procedure_list: list[AttackProcedure] = procedure_list
        self.reference_list: list[AttackExternalReference | AttackInternalReference] = reference_list

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

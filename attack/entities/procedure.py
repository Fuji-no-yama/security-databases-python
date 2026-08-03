
from .reference import AttackExternalReference, AttackInternalReference


class AttackProcedure:
    def __init__(
        self,
        original_id: str,
        parent_id: str,
        parent_name: str,
        parent_type: str,
        technique_id: str,
        description: str,
        domain: str,
        reference_list: list[AttackExternalReference | AttackInternalReference],
    ) -> None:
        self.original_id: str = original_id
        self.parent_id: str = parent_id
        self.parent_name: str = parent_name
        self.parent_type: str = parent_type
        self.technique_id: str = technique_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
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
                    if ref.id == self.parent_id:
                        desc += f'- [{i}] "{self.parent_name}" {ref.url}\n'
                    else:
                        desc += f"- [{i}] {ref.id} {ref.url}\n"
        return desc

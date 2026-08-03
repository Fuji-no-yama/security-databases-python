
from .reference import AttackExternalReference, AttackInternalReference


class AttackAbstractMitigation:  # 1つの抽象緩和策を表すクラス(具体緩和策を保有)
    def __init__(
        self,
        name: str,
        mitigation_id: str,
        description: str,
        domain: str,
        concrete_mitigation_list: list["AttackConcreteMitigation"],
        reference_list: list[AttackExternalReference | AttackInternalReference],
    ) -> None:
        self.name: str = name
        self.id: str = mitigation_id
        self.domain: str = domain
        self.description: str = description  # リンク系統を清掃する
        self.concrete_mitigation_list: list[AttackConcreteMitigation] = concrete_mitigation_list
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


class AttackConcreteMitigation:  # 1つの具体緩和策を表すクラス
    def __init__(
        self,
        abstract_mitigation_id: str,
        abstract_mitigation_name: str,
        technique_id: str,
        description: str,
        domain: str,
        reference_list: list[AttackExternalReference | AttackInternalReference],
    ) -> None:
        self.abstract_mitigation_id: str = abstract_mitigation_id
        self.abstract_mitigation_name: str = abstract_mitigation_name
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
                    if ref.id == self.abstract_mitigation_id:
                        desc += f'- [{i}] "{self.abstract_mitigation_name}" {ref.url}\n'
                    else:
                        desc += f"- [{i}] {ref.id} {ref.url}\n"
        return desc

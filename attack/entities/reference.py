class AttackExternalReference:
    def __init__(self, reference_id: int, name: str, url: str, description: str) -> None:
        self.id: int = reference_id  # 通し番号
        self.name: str = name  # 参考資料名orMITREオブジェクトのID
        self.url: str = url
        self.description: str = description  # 参考資料の説明(もしあれば)


class AttackInternalReference:
    def __init__(self, mitre_id: str, url: str) -> None:
        self.id: str = mitre_id  # MITREのオブジェクトID
        self.url: str = url  # MITREのページURL

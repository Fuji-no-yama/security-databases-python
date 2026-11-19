class AtlasAttackReference:
    """
    ATLASオブジェクトから対応するMITRE ATT&CKオブジェクトへの参照を表すクラス。

    Args:
        attack_id (str): ATT&CKのID (例: "T1596", "G0007", "S9035")
        url (str): ATT&CKのURL
    """

    def __init__(self, attack_id: str, url: str) -> None:
        self.id: str = attack_id
        self.url: str = url

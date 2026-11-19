import logging

from _security_databases.search import SearchResult

from .attack import Attack

# 公開API: ATT&CKの検索結果の型 (ATLASの AtlasSearchResult と同じ実装)
AttackSearchResult = SearchResult

# ライブラリとして標準では何も出力しない。表示したい場合は Attack(verbose=True) かロガー "attack" を設定する。
logging.getLogger("attack").addHandler(logging.NullHandler())

__all__: list[str] = ["Attack", "AttackSearchResult"]

"""ATLASの検索結果の型。実装は _security_databases.search を共有する。"""

from _security_databases.search import SearchResult

# 公開API互換のための別名
AtlasSearchResult = SearchResult

__all__: list[str] = ["AtlasSearchResult"]

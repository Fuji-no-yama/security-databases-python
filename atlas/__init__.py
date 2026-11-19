import logging

from .atlas import Atlas
from .search import AtlasSearchResult

# ライブラリとして標準では何も出力しない。表示したい場合は Atlas(verbose=True) かロガー "atlas" を設定する。
logging.getLogger("atlas").addHandler(logging.NullHandler())

__all__: list[str] = ["Atlas", "AtlasSearchResult"]

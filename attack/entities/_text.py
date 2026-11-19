"""ATT&CKオブジェクトのテキスト・辞書変換で使う補助関数。"""

import re
from typing import TYPE_CHECKING, Any

from _security_databases.render import clean_text

if TYPE_CHECKING:
    from .reference import AttackExternalReference, AttackInternalReference
    from .technique import AttackTechnique

# STIXの説明文中の引用 (例: "(Citation: Microsoft UAC)")。参照先は reference_list にあるためテキスト出力では除去する。
_STIX_CITATION = re.compile(r"\s*\(Citation: [^)]*\)")
# 整形済み説明文中の引用番号 (例: "[0]")。生の説明文が無い場合のみ除去する。
_CITATION_MARKER = re.compile(r"\s*\[\d+\]")


def description_text(raw_description: str | None, description: str | None = None) -> str:
    """
    テキスト出力・検索用の説明文を返す。

    生の説明文(STIX原文)があれば、ATT&CK内部リンクを表示名に置き換え、引用を除去して使う。
    無ければ整形済みの説明文から引用番号を除去して使う。

    Args:
        raw_description (str | None): STIXの説明文
        description (str | None): 引用を番号に整形した説明文 (生の説明文が無い場合に使う)

    Returns:
        str: 表示用の説明文
    """
    if raw_description is not None:
        return clean_text(_STIX_CITATION.sub("", raw_description))
    return clean_text(_CITATION_MARKER.sub("", description or ""))


def description_lines(raw_description: str | None, description: str | None = None) -> list[str]:
    """説明文を空行区切りのテキスト行にする。空なら何も出力しない。"""
    text = description_text(raw_description, description)
    return ["", text] if text else []


def technique_label(technique: "AttackTechnique") -> str:
    """テクニックを "ID 親テクニック名: 名前" の1行表記にする。"""
    return f"{technique.id} {technique.full_name}"


def technique_ref(technique: "AttackTechnique") -> dict[str, str]:
    """テクニックを {"id", "name"} に変換する。nameは親テクニック名を含む full_name。"""
    return {"id": technique.id, "name": technique.full_name}


def unique(items: list[Any]) -> list[Any]:
    """順序を保ったまま重複を除く。"""
    seen: set[int] = set()
    result = []
    for item in items:
        if id(item) not in seen:
            seen.add(id(item))
            result.append(item)
    return result


def reference_dicts(references: "list[AttackExternalReference | AttackInternalReference]") -> list[dict[str, str]]:
    """参照を辞書に変換する。外部参照は {"name", "url"}、ATT&CK内部参照は {"id", "url"}。"""
    result: list[dict[str, str]] = []
    for ref in references:
        name = getattr(ref, "name", None)
        result.append({"name": str(name), "url": str(ref.url)} if name is not None else {"id": str(ref.id), "url": str(ref.url)})
    return result

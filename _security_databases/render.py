"""ATLAS / ATT&CKのオブジェクトをAIエージェント向けのテキスト・辞書に変換する共通処理。"""

import html
import re
from typing import Any, Protocol

_MARKDOWN_LINK = re.compile(r"\[(.*?)\]\(.*?\)")
# 説明文中の引用マーカー (例: "[[group-profile]]")。参照先はreferencesに含まれるためテキストでは除去する。
_CITATION = re.compile(r"\s*\[\[[^\]]+\]\]")
# 書式用のHTMLタグ。データ中の "<PID>" "<filename>" のようなプレースホルダーや、攻撃例として記述された
# "<script>" "<atlas-example>" などは内容そのものであるため対象外とし、以下の書式タグのみ変換する。
_HTML_CODE = re.compile(r"<code>(.*?)</code>", re.IGNORECASE | re.DOTALL)
_HTML_BREAK = re.compile(r"<br\s*/?>", re.IGNORECASE)
_HTML_BOLD = re.compile(r"</?b>", re.IGNORECASE)
# 対になっていない <code> / </code>。上流データには "<sode>ssh_login</code>" のように開始タグが崩れた箇所があるため、
# 対として変換できなかった書式タグは除去する (データ自体は変更しない)。
_HTML_CODE_LEFTOVER = re.compile(r"</?code>", re.IGNORECASE)


class _Named(Protocol):
    id: str
    name: str


class _IdUrl(Protocol):
    id: str
    url: str


class Renderable:
    """
    to_text() / to_dict() を提供する基底クラス。

    関連オブジェクトは1段階だけ「IDと名前」で展開し、関連先の関連先は展開しない。
    これにより循環参照を避け、出力サイズを一定の範囲に保つ。
    """

    def to_dict(self) -> dict[str, Any]:
        """
        JSONシリアライズ可能な辞書に変換する。

        Returns:
            dict[str, Any]: 関連オブジェクトを {"id", "name"} で展開した辞書
        """
        raise NotImplementedError

    def to_text(self, *, max_related: int | None = None) -> str:
        """
        AIエージェントに渡しやすいテキストに変換する。

        Args:
            max_related (int | None): 関連オブジェクトの一覧ごとに表示する最大件数。Noneなら全件

        Returns:
            str: Markdown形式のテキスト
        """
        return "\n".join(self._text_lines(max_related))

    def _text_lines(self, max_related: int | None) -> list[str]:
        raise NotImplementedError


def clean_text(text: str | None) -> str:
    """
    テキスト出力用に説明文を整形する。

    - マークダウンリンクを表示テキストのみに置き換える
    - 引用マーカー (例: "[[group-profile]]") を除去する
    - 書式用のHTMLタグを変換する (<code>...</code> → `...`、<br> → 改行、<b> と対になっていない <code> は除去)
    - HTMLエンティティ (例: "&lt;", "&#35;") を文字に戻す

    Args:
        text (str | None): 元の説明文

    Returns:
        str: 整形後の説明文
    """
    result = _CITATION.sub("", _MARKDOWN_LINK.sub(r"\1", text or ""))
    result = _HTML_CODE.sub(r"`\1`", result)
    result = _HTML_BREAK.sub("\n", result)
    result = _HTML_BOLD.sub("", result)
    result = _HTML_CODE_LEFTOVER.sub("", result)
    return html.unescape(result).strip()


def ref(obj: _Named) -> dict[str, str]:
    """関連オブジェクトを {"id", "name"} に変換する。"""
    return {"id": obj.id, "name": obj.name}


def refs(objs: list[Any]) -> list[dict[str, str]]:
    """関連オブジェクトのリストを {"id", "name"} のリストに変換する。"""
    return [ref(o) for o in objs]


def label(obj: _Named) -> str:
    """関連オブジェクトを "ID 名前" の1行表記にする。"""
    return f"{obj.id} {obj.name}"


def attack_reference_dict(attack_reference: _IdUrl | None) -> dict[str, str] | None:
    """ATT&CK参照を辞書に変換する。"""
    if attack_reference is None:
        return None
    return {"id": attack_reference.id, "url": attack_reference.url}


def references_list(references: "list[Any] | None") -> list[dict[str, str]]:
    """外部参照を {"title", "url"} のリストに変換する。"""
    return [{"title": r.title, "url": r.url} for r in references or []]


def related_lines(title: str, items: list[str], max_related: int | None) -> list[str]:
    """
    関連オブジェクトの一覧をテキスト行にする。空なら何も出力しない。

    Args:
        title (str): 見出し (例: "Mitigated by")
        items (list[str]): 各行の文字列
        max_related (int | None): 最大表示件数。Noneなら全件

    Returns:
        list[str]: 空行+見出し+箇条書きの行リスト
    """
    if not items:
        return []
    shown = items if max_related is None else items[:max_related]
    lines = ["", f"{title} ({len(items)}):", *[f"- {item}" for item in shown]]
    if len(shown) < len(items):
        lines.append(f"- ... and {len(items) - len(shown)} more")
    return lines


def body_lines(description: str | None) -> list[str]:
    """説明文を空行区切りのテキスト行にする。空なら何も出力しない。"""
    text = clean_text(description)
    return ["", text] if text else []


def meta_line(*parts: str | None) -> str:
    """値のある項目だけを " | " で連結する。"""
    return " | ".join(p for p in parts if p)

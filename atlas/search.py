"""ATLASのハイブリッド検索(キーワード + ベクトル)と検索結果の表現。"""

import math
import re
from collections import Counter
from typing import Any, Generic, TypeVar

from atlas.entities._render import AtlasRenderable

T = TypeVar("T", bound=AtlasRenderable)

# 英数字の連続に加え、非ASCII文字(日本語など)の連続も1トークンとして扱う。
# ATLASのデータは英語のため日本語トークンは一致しないが、網羅率の分母に含めることで
# 英単語の一部だけが一致したクエリが高スコアにならないようにする。
_TOKEN = re.compile(r"[a-z0-9]+|[^\x00-\x7f\s]+")
_ATLAS_ID = re.compile(r"\bAML\.[A-Z]+\d+(?:\.\d+)?(?:\.S\d+)?\b", re.IGNORECASE)

# ベクトル検索が有効な場合の重み。キーワード一致は補助的に加点する。
SEMANTIC_WEIGHT = 0.75
LEXICAL_WEIGHT = 0.25
# スコア1.0はIDまたは名前の完全一致専用とし、それ以外のスコアはこの値を上限にする。
NON_EXACT_SCORE_CAP = 0.95


class AtlasSearchResult(Generic[T]):
    """
    検索結果1件を表すクラス。

    Args:
        item (T): 検索されたATLASオブジェクト
        score (float): 0〜1の関連度スコア。IDまたは名前の完全一致は1.0
    """

    def __init__(self, item: T, score: float) -> None:
        self.item: T = item
        self.score: float = score

    def to_dict(self) -> dict[str, Any]:
        """
        JSONシリアライズ可能な辞書に変換する。

        Returns:
            dict[str, Any]: item.to_dict() に "score" を加えた辞書
        """
        return {"score": round(self.score, 4), **self.item.to_dict()}

    def to_text(self, *, max_related: int | None = None) -> str:
        """
        AIエージェントに渡しやすいテキストに変換する。

        Args:
            max_related (int | None): 関連オブジェクトの一覧ごとに表示する最大件数。Noneなら全件

        Returns:
            str: 見出しにスコアを付けたMarkdown形式のテキスト
        """
        lines = self.item._text_lines(max_related)  # noqa: SLF001
        lines[0] = f"{lines[0]}  (score: {self.score:.2f})"
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"AtlasSearchResult(id={getattr(self.item, 'id', None)!r}, score={self.score:.4f})"


def tokenize(text: str) -> list[str]:
    """英数字(小文字化)と非ASCII文字の連続をトークンとして分割する。"""
    return _TOKEN.findall(text.lower())


class LexicalIndex:
    """
    BM25によるキーワード検索インデックス。

    Args:
        documents (dict[str, str]): ID -> 検索対象テキスト
    """

    _K1 = 1.5
    _B = 0.75

    def __init__(self, documents: dict[str, str]) -> None:
        self._term_freqs: dict[str, Counter[str]] = {doc_id: Counter(tokenize(text)) for doc_id, text in documents.items()}
        self._lengths: dict[str, int] = {doc_id: sum(tf.values()) for doc_id, tf in self._term_freqs.items()}
        self._avg_length: float = (sum(self._lengths.values()) / len(self._lengths)) if self._lengths else 0.0
        doc_freq: Counter[str] = Counter()
        for tf in self._term_freqs.values():
            doc_freq.update(tf.keys())
        n = len(self._term_freqs)
        self._idf: dict[str, float] = {term: math.log(1 + (n - df + 0.5) / (df + 0.5)) for term, df in doc_freq.items()}

    def scores(self, query: str) -> dict[str, float]:
        """
        クエリに対するキーワード一致スコアを返す。

        スコアは「クエリ語の網羅率(IDF加重)」×「BM25の相対値(最大値で正規化)」で、0〜1をとる。
        網羅率を掛けることで、一部の語にしか一致しない文書が満点にならないようにする。

        Args:
            query (str): 検索文言

        Returns:
            dict[str, float]: ID -> 0〜1のスコア。一致が無いIDは含まない
        """
        query_terms = set(tokenize(query))
        terms = [t for t in query_terms if t in self._idf]
        if not terms:
            return {}
        max_idf = max(self._idf.values())
        total_idf = sum(self._idf.get(t, max_idf) for t in query_terms)
        raw: dict[str, float] = {}
        coverage: dict[str, float] = {}
        for doc_id, tf in self._term_freqs.items():
            matched = [t for t in terms if tf[t]]
            if not matched:
                continue
            length_norm = self._K1 * (1 - self._B + self._B * self._lengths[doc_id] / (self._avg_length or 1))
            raw[doc_id] = sum(self._idf[t] * tf[t] * (self._K1 + 1) / (tf[t] + length_norm) for t in matched)
            coverage[doc_id] = sum(self._idf[t] for t in matched) / total_idf
        top = max(raw.values())
        return {doc_id: coverage[doc_id] * s / top for doc_id, s in raw.items()}


def exact_match_ids(query: str, names: dict[str, str]) -> set[str]:
    """
    クエリ中のATLAS IDやクエリ全体と完全一致する名前を持つIDを返す。

    Args:
        query (str): 検索文言
        names (dict[str, str]): ID -> 名前

    Returns:
        set[str]: 完全一致したID
    """
    lowered = {doc_id.lower(): doc_id for doc_id in names}
    matched = {lowered[m.lower()] for m in _ATLAS_ID.findall(query) if m.lower() in lowered}
    normalized = query.strip().casefold()
    matched |= {doc_id for doc_id, name in names.items() if name.casefold() == normalized}
    return matched


def hybrid_scores(
    query: str,
    *,
    lexical: LexicalIndex,
    names: dict[str, str],
    semantic: dict[str, float] | None,
) -> dict[str, float]:
    """
    キーワード・ベクトル・完全一致を統合した0〜1のスコアを返す。

    - IDまたは名前の完全一致: 1.0
    - ベクトル検索あり: SEMANTIC_WEIGHT * cos類似度 + LEXICAL_WEIGHT * キーワードスコア
    - ベクトル検索なし: キーワードスコアのみ
    完全一致以外は NON_EXACT_SCORE_CAP を掛けて1.0未満に収める。

    Args:
        query (str): 検索文言
        lexical (LexicalIndex): キーワード検索インデックス
        names (dict[str, str]): ID -> 名前 (完全一致判定用)
        semantic (dict[str, float] | None): ID -> cos類似度。ベクトル検索が無効ならNone

    Returns:
        dict[str, float]: ID -> スコア。スコアが0のIDは含まない
    """
    lexical_scores = lexical.scores(query)
    if semantic is None:
        combined = dict(lexical_scores)
    else:
        combined = {
            doc_id: SEMANTIC_WEIGHT * max(semantic.get(doc_id, 0.0), 0.0) + LEXICAL_WEIGHT * lexical_scores.get(doc_id, 0.0)
            for doc_id in set(semantic) | set(lexical_scores)
        }
    scores = {doc_id: NON_EXACT_SCORE_CAP * min(s, 1.0) for doc_id, s in combined.items()}
    for doc_id in exact_match_ids(query, names):
        scores[doc_id] = 1.0
    return {doc_id: s for doc_id, s in scores.items() if s > 0}

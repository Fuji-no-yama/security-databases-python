"""ATLASのv6形式データをロードするクラス。"""

import hashlib
import logging
import re
import sys
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast, get_args

import yaml
from platformdirs import user_data_dir

from _security_databases.embedding import (
    EmbeddingModel,
    EmbeddingProvider,
    create_embedding_function,
    resolve_embedding_configuration,
)
from _security_databases.render import Renderable
from _security_databases.search import LexicalIndex, compute_scores
from _security_databases.vector_index import IndexSpec, VectorIndex
from atlas import version_resolver
from atlas.entities import (
    AtlasAssociatedEntity,
    AtlasAttackReference,
    AtlasCaseStudy,
    AtlasCaseStudyAttribution,
    AtlasCaseStudyStep,
    AtlasEntity,
    AtlasMitigation,
    AtlasReference,
    AtlasRelationship,
    AtlasSoftware,
    AtlasTactic,
    AtlasTechnique,
    RelationshipType,
)
from atlas.search import AtlasSearchResult

if TYPE_CHECKING:
    from importlib.abc import Traversable

T = TypeVar("T", bound=Renderable)

logger = logging.getLogger("atlas")
# ベクトル化する文章の作り方やコレクション構成を変えたら上げる。既存のベクトルDBは次回起動時に自動で再構築される。
_INDEX_VERSION = "2"
# クエリからATLAS IDを抽出する正規表現 (例: "AML.T0051", "AML.CS0044.S05")
_ATLAS_ID_PATTERN = re.compile(r"\bAML\.[A-Z]+\d+(?:\.\d+)?(?:\.S\d+)?\b", re.IGNORECASE)
_verbose_handler: logging.Handler | None = None

# format-version 6.1.0 でケーススタディの項目名が変更されたもの (旧名 -> 新名)。
# 値の推測ではなく上流CHANGELOGに記載された同義の名称変更のみを読み替える。
_RENAMED_CASE_STUDY_KEYS: dict[str, str] = {
    "date": "start-date",
    "date-granularity": "start-date-granularity",
}

SearchKind = Literal["technique", "mitigation", "case_study", "case_study_step"]
_COLLECTION_NAMES: dict[SearchKind, str] = {
    "technique": "atlas_technique",
    "mitigation": "atlas_mitigation",
    "case_study": "atlas_case_study",
    "case_study_step": "atlas_case_study_step",
}


def _enable_verbose_logging() -> None:
    """ロガー "atlas" の INFO 以上を標準エラー出力に表示する。"""
    global _verbose_handler  # noqa: PLW0603
    if _verbose_handler is None:
        _verbose_handler = logging.StreamHandler(sys.stderr)
        _verbose_handler.setFormatter(logging.Formatter("[atlas] %(message)s"))
        logger.addHandler(_verbose_handler)
    logger.setLevel(logging.INFO)


class Atlas:
    """
    ATLASのv6データを保持しアクセスAPIを提供するクラス。

    Args:
        version (str | None): リリース識別子 (例: "2026.06") または
            旧format-version (例: "5.6.0")。Noneの場合はmanifest.yaml先頭の最新リリース。
            旧format-versionを指定した場合はmanifest経由で同一リリースのv6ファイルにフォールバックする。
        emb_model (str): OpenAI providerでベクトル化に使用するモデル。Azure OpenAIではdeployment設定を使用する
        embedding_provider (str): "openai"または"azure_openai"
        initialize_vector (bool): TrueならベクトルDBを強制的に再構築する。
            通常はデータやライブラリの更新を検知して自動で再構築されるため指定不要
        verbose (bool): TrueならベクトルDB構築などの進捗を標準エラー出力に表示する。
            Falseの場合は何も出力しない(ロガー名 "atlas" で制御可能)
    """

    def __init__(
        self,
        *,
        version: str | None = None,
        emb_model: EmbeddingModel = "text-embedding-3-large",
        embedding_provider: EmbeddingProvider = "openai",
        initialize_vector: bool = False,
        verbose: bool = False,
    ) -> None:
        if verbose:
            _enable_verbose_logging()
        release_input: str = version if version is not None else version_resolver.latest_release()
        release, v6_path = version_resolver.resolve(release_input)
        self.release: str = release
        self.version: str = f"v{release}"
        self.data_file: Traversable = files("atlas.data").joinpath(v6_path)
        self.user_data_dir_path: Path = Path(user_data_dir("atlas")) / "releases" / release

        data_bytes: bytes = self.data_file.read_bytes()
        self._raw: dict[str, Any] = yaml.safe_load(data_bytes)

        self.__create_tactic_list()
        self.__create_tec_list()
        self.__create_mit_list()
        self.__create_entity_list()
        self.__create_software_list()
        self.__create_casestudy_list()
        self.__build_relationships()
        self.__apply_relationships()
        self.__build_search_documents()

        self._vector_index: VectorIndex | None = None
        embedding_configuration = resolve_embedding_configuration(embedding_provider, emb_model)
        if embedding_configuration is not None:
            self.chroma_path: Path = self.user_data_dir_path / "chroma" / embedding_configuration.cache_key
            self.chroma_path.mkdir(parents=True, exist_ok=True)
            self._vector_index = VectorIndex(
                self.chroma_path,
                create_embedding_function(embedding_configuration),
                data_hash=hashlib.sha256(data_bytes).hexdigest()[:16],
                index_version=_INDEX_VERSION,
                logger_name="atlas",
                show_progress=verbose,
            )
            self._vector_index.ensure(self.__index_specs(), force_rebuild=initialize_vector)
        else:
            logger.info("Embedding providerの設定がないため、キーワード検索のみで動作します。")

    @property
    def vector_search_enabled(self) -> bool:
        """ベクトル検索が有効かどうか。Falseの場合、search_relevant系はキーワード検索のみで動作する。"""
        return self._vector_index is not None

    @staticmethod
    def _make_references(raw: list[dict[str, Any]] | None) -> list[AtlasReference] | None:
        if not raw:
            return None
        refs: list[AtlasReference] = []
        for r in raw:
            title = r.get("title")
            url = r.get("url")
            if title is None or url is None:
                continue
            refs.append(AtlasReference(title=str(title), url=str(url), ref_id=r.get("id")))
        return refs or None

    @staticmethod
    def _make_attack_reference(raw: dict[str, Any] | None) -> AtlasAttackReference | None:
        if not raw or raw.get("id") is None or raw.get("url") is None:
            return None
        return AtlasAttackReference(attack_id=str(raw["id"]), url=str(raw["url"]))

    def __create_tactic_list(self) -> None:
        self.tactic_list: list[AtlasTactic] = []
        self._tactics_by_id: dict[str, AtlasTactic] = {}
        for tid, td in self._raw.get("tactics", {}).items():
            tac = AtlasTactic(
                tactic_id=tid,
                name=td["name"],
                description=td["description"],
                tec_lis=[],
                uuid=td.get("uuid"),
                references=self._make_references(td.get("references")),
            )
            self.tactic_list.append(tac)
            self._tactics_by_id[tid] = tac

    def __create_tec_list(self) -> None:
        self.technique_list: list[AtlasTechnique] = []
        self._techniques_by_id: dict[str, AtlasTechnique] = {}
        for tid, td in self._raw.get("techniques", {}).items():
            tec = AtlasTechnique(
                name=td["name"],
                technique_id=tid,
                description=td["description"],
                have_parent=False,
                parent_id=None,
                tactics=[],
                uuid=td.get("uuid"),
                references=self._make_references(td.get("references")),
                platforms=td.get("platforms"),
                maturity=td.get("maturity"),
                attack_reference=self._make_attack_reference(td.get("attack-reference")),
            )
            self.technique_list.append(tec)
            self._techniques_by_id[tid] = tec

    def __create_mit_list(self) -> None:
        self.mitigation_list: list[AtlasMitigation] = []
        self._mitigations_by_id: dict[str, AtlasMitigation] = {}
        for mid, md in self._raw.get("mitigations", {}).items():
            mit = AtlasMitigation(
                mitigation_id=mid,
                name=md["name"],
                description=md["description"],
                tec_lis=[],
                uuid=md.get("uuid"),
                references=self._make_references(md.get("references")),
            )
            self.mitigation_list.append(mit)
            self._mitigations_by_id[mid] = mit

    def __create_entity_list(self) -> None:
        self.entity_list: list[AtlasEntity] = []
        self._entities_by_id: dict[str, AtlasEntity] = {}
        for eid, ed in (self._raw.get("entities") or {}).items():
            ent = AtlasEntity(
                entity_id=eid,
                name=ed["name"],
                description=ed.get("description", ""),
                entity_type=ed["entity-type"],
                associated_entities=[
                    AtlasAssociatedEntity(name=str(a["name"]), description=a.get("description")) for a in ed.get("associated-entities") or []
                ],
                attack_reference=self._make_attack_reference(ed.get("attack-reference")),
                uuid=ed.get("uuid"),
                references=self._make_references(ed.get("references")),
                created_date=ed.get("created-date"),
                modified_date=ed.get("modified-date"),
            )
            self.entity_list.append(ent)
            self._entities_by_id[eid] = ent

    def __create_software_list(self) -> None:
        self.software_list: list[AtlasSoftware] = []
        self._software_by_id: dict[str, AtlasSoftware] = {}
        for sid, sd in (self._raw.get("software") or {}).items():
            sw = AtlasSoftware(
                software_id=sid,
                name=sd["name"],
                description=sd.get("description", ""),
                software_type=sd["software-type"],
                software_categories=sd.get("software-categories"),
                aliases=sd.get("aliases"),
                attack_reference=self._make_attack_reference(sd.get("attack-reference")),
                uuid=sd.get("uuid"),
                references=self._make_references(sd.get("references")),
                created_date=sd.get("created-date"),
                modified_date=sd.get("modified-date"),
            )
            self.software_list.append(sw)
            self._software_by_id[sid] = sw

    def __create_casestudy_list(self) -> None:
        self.casestudy_list: list[AtlasCaseStudy] = []
        self._casestudies_by_id: dict[str, AtlasCaseStudy] = {}
        for cid, raw_cd in self._raw.get("case-studies", {}).items():
            cd: dict[str, Any] = {_RENAMED_CASE_STUDY_KEYS.get(k, k): v for k, v in raw_cd.items()}
            refs = self._make_references(cd.get("references"))
            cs_type = cd.get("type", "Exercise")
            cs = AtlasCaseStudy(
                casestudy_id=cid,
                name=cd["name"],
                summary=cd.get("description", ""),
                step_list=[],
                target=cd.get("target", ""),
                actor=cd.get("actor", ""),
                casestudy_type=cs_type,
                reference_title_list=[r.title for r in refs] if refs else None,
                reference_url_list=[r.url for r in refs] if refs else None,
                uuid=cd.get("uuid"),
                references=refs,
                reporter=cd.get("reporter"),
                start_date=cd.get("start-date"),
                start_date_granularity=cd.get("start-date-granularity"),
                end_date=cd.get("end-date"),
                end_date_granularity=cd.get("end-date-granularity"),
            )
            self.casestudy_list.append(cs)
            self._casestudies_by_id[cid] = cs

    def __build_relationships(self) -> None:
        """v6の relationships セクションを AtlasRelationship のフラットリストに正規化する。"""
        self.relationships: list[AtlasRelationship] = []
        raw_relationships: dict[str, dict[str, list[dict[str, Any]]]] = self._raw.get("relationships", {})
        known_types: set[str] = set(get_args(RelationshipType))
        for groups in raw_relationships.values():
            for rel_type, entries in groups.items():
                if rel_type not in known_types:
                    continue
                for rel in entries:
                    self.relationships.append(
                        AtlasRelationship(
                            source_id=str(rel["source"]),
                            target_id=str(rel["target"]),
                            type=cast("RelationshipType", rel_type),
                            description=rel.get("description"),
                            activity_purpose=rel.get("activity-purpose"),
                            tactic_id=rel.get("tactic"),
                            step_id=rel.get("step-id"),
                            leads_to=rel.get("leads-to"),
                            position=rel.get("position"),
                            uuid=rel.get("uuid"),
                            references=self._make_references(rel.get("references")),
                            raw=rel,
                        ),
                    )

    def __apply_relationships(self) -> None:
        """self.relationships をもとに派生ビュー(technique.tactics 等)を materialize する。"""
        for rel in self.relationships:
            if rel.type == "achieves":
                self.__apply_achieves_relationship(rel)
            elif rel.type == "mitigates":
                self.__apply_mitigates_relationship(rel)
            elif rel.type == "employs":
                self.__apply_employs_relationship(rel)
            elif rel.type in ("attributed-to", "reported-by"):
                self.__apply_casestudy_entity_relationship(rel)
            elif rel.type == "uses":
                self.__apply_uses_relationship(rel)
            elif rel.type == "implements":
                self.__apply_implements_relationship(rel)

        self.__apply_technique_hierarchy()

        for cs in self.casestudy_list:
            cs.procedure.sort(key=lambda s: s.step_id or "")

    def __apply_achieves_relationship(self, rel: AtlasRelationship) -> None:
        """achieves (Technique → Tactic) を反映する。"""
        tec = self._techniques_by_id.get(rel.source_id)
        tac = self._tactics_by_id.get(rel.target_id)
        if tec is None or tac is None:
            return
        if tac not in tec.tactics:
            tec.tactics.append(tac)
        if tec not in tac.technique_list:
            tac.technique_list.append(tec)

    def __apply_mitigates_relationship(self, rel: AtlasRelationship) -> None:
        """mitigates (Mitigation → Technique) を反映し、Technique 側にも逆引きを設定する。"""
        mit = self._mitigations_by_id.get(rel.source_id)
        tec = self._techniques_by_id.get(rel.target_id)
        if mit is None or tec is None:
            return
        if tec not in mit.technique_list:
            mit.technique_list.append(tec)
        if mit not in tec.mitigation_list:
            tec.mitigation_list.append(mit)

    def __apply_employs_relationship(self, rel: AtlasRelationship) -> None:
        """employs (CaseStudy → Technique) をケーススタディのステップとして反映する。"""
        cs = self._casestudies_by_id.get(rel.source_id)
        tec = self._techniques_by_id.get(rel.target_id)
        tac = self._tactics_by_id.get(rel.tactic_id) if rel.tactic_id else None
        if cs is None or tec is None or tac is None:
            return
        step = AtlasCaseStudyStep(
            casestudy_step_id=f"{cs.id}.{rel.step_id or ''}",
            tactic=tac,
            technique=tec,
            description=rel.description or "",
            parent_id=cs.id,
            step_id=rel.step_id,
            leads_to=rel.leads_to,
        )
        step.casestudy = cs
        cs.procedure.append(step)
        if cs not in tec.casestudy_list:
            tec.casestudy_list.append(cs)

    def __apply_casestudy_entity_relationship(self, rel: AtlasRelationship) -> None:
        """attributed-to / reported-by (CaseStudy → Entity) を反映する。"""
        cs = self._casestudies_by_id.get(rel.source_id)
        ent = self._entities_by_id.get(rel.target_id)
        if cs is None or ent is None:
            return
        if rel.type == "attributed-to":
            cs.attributions.append(
                AtlasCaseStudyAttribution(entity=ent, activity_purpose=rel.activity_purpose, description=rel.description),
            )
            if cs not in ent.casestudy_list:
                ent.casestudy_list.append(cs)
        else:
            if ent not in cs.reported_by:
                cs.reported_by.append(ent)
            if cs not in ent.reported_casestudy_list:
                ent.reported_casestudy_list.append(cs)

    def __apply_uses_relationship(self, rel: AtlasRelationship) -> None:
        """uses (CaseStudy → Software / Entity → Software / Entity → Technique) を反映する。"""
        sw = self._software_by_id.get(rel.target_id)
        tec = self._techniques_by_id.get(rel.target_id)
        source_cs = self._casestudies_by_id.get(rel.source_id)
        source_ent = self._entities_by_id.get(rel.source_id)
        if source_cs is not None and sw is not None:
            if sw not in source_cs.software_list:
                source_cs.software_list.append(sw)
            if source_cs not in sw.casestudy_list:
                sw.casestudy_list.append(source_cs)
        elif source_ent is not None and sw is not None:
            if sw not in source_ent.software_list:
                source_ent.software_list.append(sw)
            if source_ent not in sw.entity_list:
                sw.entity_list.append(source_ent)
        elif source_ent is not None and tec is not None and tec not in source_ent.technique_list:
            source_ent.technique_list.append(tec)

    def __apply_implements_relationship(self, rel: AtlasRelationship) -> None:
        """implements (Software → Technique) を反映し、Technique 側にも逆引きを設定する。"""
        sw = self._software_by_id.get(rel.source_id)
        tec = self._techniques_by_id.get(rel.target_id)
        if sw is None or tec is None:
            return
        if tec not in sw.technique_list:
            sw.technique_list.append(tec)
        if sw not in tec.software_list:
            tec.software_list.append(sw)

    def __apply_technique_hierarchy(self) -> None:
        """specializes (サブテクニック → 親テクニック) を反映する。"""
        for rel in self.relationships:
            if rel.type != "specializes":
                continue
            child = self._techniques_by_id.get(rel.source_id)
            parent = self._techniques_by_id.get(rel.target_id)
            if child is not None and parent is not None:
                self.__link_subtechnique(child, parent)

        # 旧v6リリース(specializes未導入)向けのフォールバック: ID命名規則 "AML.T####.###" からサブテクニックを推定
        subtechnique_parts_count: int = 3
        for tec in self.technique_list:
            if tec.have_parent:
                continue
            parts: list[str] = tec.id.split(".")
            if len(parts) >= subtechnique_parts_count and parts[0] == "AML" and parts[1].startswith("T"):
                parent_tec = self._techniques_by_id.get(".".join(parts[:2]))
                if parent_tec is not None:
                    self.__link_subtechnique(tec, parent_tec)

    @staticmethod
    def __link_subtechnique(child: AtlasTechnique, parent: AtlasTechnique) -> None:
        child.have_parent = True
        child.parent_id = parent.id
        child.parent = parent
        if child not in parent.subtechnique_list:
            parent.subtechnique_list.append(child)

    def __build_search_documents(self) -> None:
        """検索対象(テクニック・緩和策・ケーススタディ・ステップ)ごとのテキストとキーワードインデックスを作る。"""
        self._search_items: dict[SearchKind, dict[str, Any]] = {
            "technique": self._techniques_by_id,
            "mitigation": self._mitigations_by_id,
            "case_study": self._casestudies_by_id,
            "case_study_step": {step.id: step for cs in self.casestudy_list for step in cs.procedure},
        }
        self._search_documents: dict[SearchKind, dict[str, str]] = {
            "technique": {t.id: f"{t.name}\n\n{t.description}" for t in self.technique_list},
            "mitigation": {m.id: f"{m.name}\n\n{m.description}" for m in self.mitigation_list},
            "case_study": {cs.id: self.__case_study_document(cs) for cs in self.casestudy_list},
            "case_study_step": {step.id: f"{step.technique.name}\n\n{step.description}" for cs in self.casestudy_list for step in cs.procedure},
        }
        self._search_names: dict[SearchKind, dict[str, str]] = {
            "technique": {t.id: t.name for t in self.technique_list},
            "mitigation": {m.id: m.name for m in self.mitigation_list},
            "case_study": {cs.id: cs.name for cs in self.casestudy_list},
            "case_study_step": {},
        }
        self._lexical_indexes: dict[SearchKind, LexicalIndex] = {kind: LexicalIndex(documents) for kind, documents in self._search_documents.items()}

    @staticmethod
    def __case_study_document(cs: AtlasCaseStudy) -> str:
        parts = [cs.name, f"Target: {cs.target}" if cs.target else ""]
        entities = [a.entity.name for a in cs.attributions]
        if entities:
            parts.append(f"Attributed to: {', '.join(entities)}")
        if cs.software_list:
            parts.append(f"Software: {', '.join(s.name for s in cs.software_list)}")
        parts.append(cs.summary)
        return "\n\n".join(p for p in parts if p)

    def __index_specs(self) -> list[IndexSpec]:
        return [
            IndexSpec(name=_COLLECTION_NAMES[kind], ids=list(documents.keys()), documents=list(documents.values()))
            for kind, documents in self._search_documents.items()
        ]

    def __search(self, kind: SearchKind, query: str, top_k: int, candidates: dict[str, T]) -> list[AtlasSearchResult[T]]:
        if top_k <= 0:
            err_msg = f"top_kは1以上を指定してください: {top_k}"
            raise ValueError(err_msg)
        semantic = self._vector_index.similarities(_COLLECTION_NAMES[kind], query) if self._vector_index is not None else None
        scores = compute_scores(
            query,
            lexical=self._lexical_indexes[kind],
            names=self._search_names[kind],
            semantic=semantic,
            id_pattern=_ATLAS_ID_PATTERN,
        )
        ranked = sorted((doc_id for doc_id in scores if doc_id in candidates), key=lambda doc_id: (-scores[doc_id], doc_id))
        return [AtlasSearchResult(candidates[doc_id], scores[doc_id]) for doc_id in ranked[:top_k]]

    def get_relationships(
        self,
        *,
        source_id: str | None = None,
        target_id: str | None = None,
        type: RelationshipType | None = None,  # noqa: A002
    ) -> list[AtlasRelationship]:
        """
        self.relationships を source_id / target_id / type で絞り込んだリストを返す。

        Args:
            source_id (str | None): 起点エンティティIDでフィルタ
            target_id (str | None): 対象エンティティIDでフィルタ
            type (RelationshipType | None): 関係種別でフィルタ

        Returns:
            list[AtlasRelationship]: 条件に一致するrelationshipのリスト
        """
        result: list[AtlasRelationship] = []
        for rel in self.relationships:
            if source_id is not None and rel.source_id != source_id:
                continue
            if target_id is not None and rel.target_id != target_id:
                continue
            if type is not None and rel.type != type:
                continue
            result.append(rel)
        return result

    @staticmethod
    def __get_or_raise(items: dict[str, T], item_id: str) -> T:
        item = items.get(item_id)
        if item is None:
            err_msg = f"'{item_id}'が検索の結果見つかりませんでした。"
            raise ValueError(err_msg)
        return item

    def get_technique_by_id(self, tec_id: str) -> AtlasTechnique:
        """
        IDからテクニックを検索する。

        Args:
            tec_id (str): テクニックのID (例: "AML.T0042")

        Returns:
            AtlasTechnique: 検索されたテクニックオブジェクト
        """
        return self.__get_or_raise(self._techniques_by_id, tec_id)

    def get_tactic_by_id(self, tac_id: str) -> AtlasTactic:
        """
        IDからタクティックを検索する。

        Args:
            tac_id (str): タクティックのID (例: "AML.TA0001")

        Returns:
            AtlasTactic: 検索されたタクティックオブジェクト
        """
        return self.__get_or_raise(self._tactics_by_id, tac_id)

    def get_mitigation_by_id(self, mit_id: str) -> AtlasMitigation:
        """
        IDから緩和策を検索する。

        Args:
            mit_id (str): 緩和策のID (例: "AML.M0000")

        Returns:
            AtlasMitigation: 検索された緩和策オブジェクト
        """
        return self.__get_or_raise(self._mitigations_by_id, mit_id)

    def get_case_study_by_id(self, cs_id: str) -> AtlasCaseStudy:
        """
        IDからケーススタディを検索する。

        Args:
            cs_id (str): ケーススタディのID (例: "AML.CS0026")

        Returns:
            AtlasCaseStudy: 検索されたケーススタディオブジェクト
        """
        return self.__get_or_raise(self._casestudies_by_id, cs_id)

    def get_case_study_step_by_id(self, cs_step_id: str) -> AtlasCaseStudyStep:
        """
        ケーススタディIDとステップIDからステップを検索する。

        Args:
            cs_step_id (str): ケーススタディID+ステップID (例: "AML.CS0000.S00")

        Returns:
            AtlasCaseStudyStep: 検索されたステップオブジェクト
        """
        return self.__get_or_raise(self._search_items["case_study_step"], cs_step_id)

    def get_entity_by_id(self, entity_id: str) -> AtlasEntity:
        """
        IDからエンティティを検索する。format-version 6.1.0より前のリリースにはエンティティが存在しない。

        Args:
            entity_id (str): エンティティのID (例: "AML.E0018")

        Returns:
            AtlasEntity: 検索されたエンティティオブジェクト
        """
        return self.__get_or_raise(self._entities_by_id, entity_id)

    def get_software_by_id(self, software_id: str) -> AtlasSoftware:
        """
        IDからソフトウェアを検索する。format-version 6.1.0より前のリリースにはソフトウェアが存在しない。

        Args:
            software_id (str): ソフトウェアのID (例: "AML.S0015")

        Returns:
            AtlasSoftware: 検索されたソフトウェアオブジェクト
        """
        return self.__get_or_raise(self._software_by_id, software_id)

    def search_relevant_techniques(
        self,
        query: str,
        top_k: int,
        *,
        filter: Literal["parent", "child", "both"] = "both",  # noqa: A002
        tactic_id: str | None = None,
        platform: str | None = None,
        maturity: str | None = None,
    ) -> list[AtlasSearchResult[AtlasTechnique]]:
        """
        クエリに関連するテクニックを検索する。

        ベクトル検索(名前+説明文のcos類似度)で順位を付け、IDまたは名前の完全一致は最上位(スコア1.0)にする。
        Embedding未設定時はベクトル検索の代わりにキーワード検索(BM25)を使う。
        データが英語のため英語のクエリを推奨する。

        Args:
            query (str): 検索文言 (自然文、名前、ID "AML.T0051" など)
            top_k (int): 上位取得件数
            filter (str): "parent"(親テクニックのみ) / "child"(サブテクニックのみ) / "both"
            tactic_id (str | None): 指定したタクティックに属するテクニックに絞り込む (例: "AML.TA0002")
            platform (str | None): 指定したプラットフォームを持つテクニックに絞り込む (例: "Agentic AI")
            maturity (str | None): 成熟度で絞り込む ("Feasible" / "Demonstrated" / "Realized")

        Returns:
            list[AtlasSearchResult[AtlasTechnique]]: スコア降順の検索結果
        """
        candidates = {
            tec.id: tec
            for tec in self.technique_list
            if (filter == "both" or (filter == "parent") != tec.have_parent)
            and (tactic_id is None or any(t.id == tactic_id for t in tec.tactics))
            and (platform is None or platform in (tec.platforms or []))
            and (maturity is None or tec.maturity == maturity)
        }
        return self.__search("technique", query, top_k, candidates)

    def search_relevant_mitigations(self, query: str, top_k: int) -> list[AtlasSearchResult[AtlasMitigation]]:
        """
        クエリに関連する緩和策を検索する。

        Args:
            query (str): 検索文言
            top_k (int): 上位取得件数

        Returns:
            list[AtlasSearchResult[AtlasMitigation]]: スコア降順の検索結果
        """
        return self.__search("mitigation", query, top_k, self._mitigations_by_id)

    def search_relevant_case_studies(
        self,
        query: str,
        top_k: int,
        *,
        casestudy_type: Literal["Exercise", "Incident"] | None = None,
    ) -> list[AtlasSearchResult[AtlasCaseStudy]]:
        """
        クエリに関連するケーススタディを検索する。

        名前・対象・帰属先エンティティ・使用ソフトウェア・概要を検索対象とする。

        Args:
            query (str): 検索文言
            top_k (int): 上位取得件数
            casestudy_type (str | None): "Exercise" または "Incident" で絞り込む

        Returns:
            list[AtlasSearchResult[AtlasCaseStudy]]: スコア降順の検索結果
        """
        candidates = {cs.id: cs for cs in self.casestudy_list if casestudy_type is None or cs.type == casestudy_type}
        return self.__search("case_study", query, top_k, candidates)

    def search_relevant_case_study_steps(self, query: str, top_k: int) -> list[AtlasSearchResult[AtlasCaseStudyStep]]:
        """
        クエリに関連するケーススタディのステップを検索する。

        あるテクニックが実際にどのように使われたかを調べる用途を想定する。

        Args:
            query (str): 検索文言
            top_k (int): 上位取得件数

        Returns:
            list[AtlasSearchResult[AtlasCaseStudyStep]]: スコア降順の検索結果
        """
        return self.__search("case_study_step", query, top_k, self._search_items["case_study_step"])

    def get_available_versions(self) -> list[str]:
        """
        利用可能なATLASリリース一覧を返す(v6形式のrelease識別子のみ)。

        Returns:
            list[str]: 昇順ソートされたrelease識別子のリスト
        """
        return version_resolver.list_releases()

    def get_available_legacy_versions(self) -> list[str]:
        """
        version引数に指定可能な旧format-version(legacy)一覧を返す。

        Returns:
            list[str]: 昇順ソートされた旧format-versionのリスト
        """
        return version_resolver.list_legacy_versions()

import re
import shutil
from contextlib import suppress
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import chromadb
from chromadb.api.models.Collection import Collection
from chromadb.errors import NotFoundError
from platformdirs import user_data_dir
from tqdm import tqdm

from _security_databases.embedding import (
    EmbeddingModel,
    EmbeddingProvider,
    create_embedding_function,
    resolve_embedding_configuration,
)
from attack import version_resolver
from attack.entities import (
    AttackAbstractMitigation,
    AttackCampaign,
    AttackConcreteMitigation,
    AttackExternalReference,
    AttackGroup,
    AttackInternalReference,
    AttackProcedure,
    AttackRelationship,
    AttackSoftware,
    AttackTactic,
    AttackTechnique,
)
from attack.stix_bundle import StixBundle, attack_id_of, attack_url_of

if TYPE_CHECKING:
    from importlib.abc import Traversable

# ドメインごとのkill chain名 (テクニックとタクティックの対応付けに使う)
_KILL_CHAIN_NAMES: dict[str, str] = {
    "enterprise": "mitre-attack",
    "mobile": "mitre-mobile-attack",
    "ics": "mitre-ics-attack",
}
# ベクトルDBの保存先ディレクトリ名。Excel版とSTIX版でプロシージャID (P0001...) の採番順が異なるため、
# Excel版で作成した "chroma" 配下のDBを誤って使わないよう、STIX版では別ディレクトリに作成する。
_VECTOR_DB_DIR = "chroma-stix"
# プロシージャ(uses relationship)の起点になり得るSTIX typeと、AttackProcedure.parent_type の対応
_PROCEDURE_PARENT_TYPES: dict[str, str] = {
    "campaign": "campaign",
    "malware": "software",
    "tool": "software",
    "intrusion-set": "group",
}


class Attack:
    version: str
    domain: str
    technique_list: list[AttackTechnique]
    tactic_list: list[AttackTactic]
    mitigation_list: list[AttackAbstractMitigation]

    def __init__(
        self,
        *,  # 以下をキーワード引数に
        domain: str = "enterprise",
        version: str | None = None,
        emb_model: EmbeddingModel = "text-embedding-3-large",
        embedding_provider: EmbeddingProvider = "openai",
        initialize_vector: bool = False,
    ) -> None:
        """
        Args:
            domain (str): ATT&CKドメイン ("enterprise", "mobile", "ics"のいずれか) defaultはenterprise
            version (str | None): ATTACKデータバージョン。Noneの場合はmanifest.yamlのlatest
            emb_model (str): OpenAI providerでベクトル化に使用するモデル。Azure OpenAIではdeployment設定を使用する
            embedding_provider (str): "openai"または"azure_openai"
            initialize_vector (bool): ベクトルDBを初期化するかどうか(デフォルトはFalse。TrueにするとベクトルDBを再構築する)
        """  # noqa: E501
        available_domains: list[str] = version_resolver.list_domains()
        if domain not in available_domains:
            err_msg = f"domain must be one of {available_domains}."
            raise ValueError(err_msg)
        self.procedure_count = 0
        self.domain = domain
        version_input = version if version is not None else version_resolver.latest_version()
        resolved_version, data_path = version_resolver.resolve(version_input)
        self.release = resolved_version
        self.version = f"v{resolved_version}"
        self.data_file: Traversable = files("attack.data").joinpath(data_path).joinpath(f"{domain}-attack-{resolved_version}.json.gz")
        self.user_data_dir_path: Path = Path(user_data_dir("attack")) / "releases" / resolved_version / domain
        self.user_data_dir_path.mkdir(parents=True, exist_ok=True)  # 念の為作成

        self._bundle = StixBundle(self.data_file)
        self.external_reference_list: list[AttackExternalReference] = self.__setup_external_reference_list()
        self.tactic_list: list[AttackTactic] = self.__setup_tactic_list()
        self.technique_list: list[AttackTechnique] = self.__setup_technique_list()
        self.mitigation_list: list[AttackAbstractMitigation] = self.__setup_mitigation_list()
        self.campaign_list: list[AttackCampaign] = self.__setup_campaign_list()
        self.software_list: list[AttackSoftware] = self.__setup_software_list()
        self.group_list: list[AttackGroup] = self.__setup_group_list()
        self.relationships: list[AttackRelationship] = self.__setup_relationships()
        self.__link_entities()

        self.technique_chroma_collection: Collection | None = None
        self.procedure_chroma_collection: Collection | None = None

        embedding_configuration = resolve_embedding_configuration(embedding_provider, emb_model)
        if embedding_configuration is not None:
            self._embedding_function = create_embedding_function(embedding_configuration)
            self.chroma_path = self.user_data_dir_path / _VECTOR_DB_DIR / embedding_configuration.cache_key
            has_vector_db = self.chroma_path.is_dir()
            if not has_vector_db:
                print("ベクトルDBの設定がありません。初期化し作成します...")
                initialize_vector = True
            self.chroma_client = chromadb.PersistentClient(str(self.chroma_path))
            if initialize_vector:
                self.__initialize_vector()
            self.technique_chroma_collection = self.__get_technique_chroma_collection()
            self.procedure_chroma_collection = self.__get_procedure_chroma_collection()

    def __setup_external_reference_list(self) -> list[AttackExternalReference]:
        return [
            AttackExternalReference(
                reference_id=i,
                name=name,
                url=str(ref.get("url", "")),
                description=str(ref.get("description", "")),
            )
            for i, (name, ref) in enumerate(self._bundle.citations.items())
        ]

    def __setup_tactic_list(self) -> list[AttackTactic]:
        """タクティックを作成する。マトリクスに定義された順 (攻撃の段階順) に並べる。"""
        order: list[str] = [ref for matrix in self._bundle.objects_by_type.get("x-mitre-matrix", []) for ref in matrix.get("tactic_refs", [])]
        tactics = self._bundle.of_type("x-mitre-tactic")
        tactics.sort(key=lambda o: order.index(o["id"]) if o["id"] in order else len(order))
        return [
            AttackTactic(
                tactic_id=attack_id_of(obj) or "",
                name=obj["name"],
                domain=self.domain,
                description=obj.get("description", ""),
                technique_list=[],
                shortname=obj.get("x_mitre_shortname"),
                stix_id=obj["id"],
            )
            for obj in tactics
        ]

    def __setup_technique_list(self) -> list[AttackTechnique]:
        tactics_by_shortname: dict[str, AttackTactic] = {t.shortname: t for t in self.tactic_list if t.shortname}
        kill_chain_name = _KILL_CHAIN_NAMES[self.domain]
        technique_list: list[AttackTechnique] = []
        for obj in self._bundle.of_type("attack-pattern"):
            description: str = obj.get("description", "")
            tactics = [
                tactics_by_shortname[phase["phase_name"]]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == kill_chain_name and phase.get("phase_name") in tactics_by_shortname
            ]
            tec = AttackTechnique(
                name=obj["name"],
                technique_id=attack_id_of(obj) or "",
                description=self.__clean_description(description),
                domain=self.domain,
                tactics=tactics,
                reference_list=self.__create_reference_list(description),
                stix_id=obj["id"],
                platforms=obj.get("x_mitre_platforms"),
                url=attack_url_of(obj),
            )
            technique_list.append(tec)
            for tactic in tactics:
                tactic.technique_list.append(tec)
        return technique_list

    def __setup_mitigation_list(self) -> list[AttackAbstractMitigation]:
        mitigates_by_source: dict[str, list[dict[str, Any]]] = {}
        for rel in self._bundle.relationships_of("mitigates"):
            mitigates_by_source.setdefault(rel["source_ref"], []).append(rel)
        mitigation_list: list[AttackAbstractMitigation] = []
        for obj in self._bundle.of_type("course-of-action"):
            mitigation_id = attack_id_of(obj) or ""
            description: str = obj.get("description", "")
            concrete_mitigation_list: list[AttackConcreteMitigation] = []
            for rel in sorted(mitigates_by_source.get(obj["id"], []), key=self.__target_attack_id):
                technique_id = self.__target_attack_id(rel)
                if not technique_id:
                    continue
                rel_description: str = rel.get("description", "")
                concrete_mitigation_list.append(
                    AttackConcreteMitigation(
                        abstract_mitigation_id=mitigation_id,
                        abstract_mitigation_name=obj["name"],
                        technique_id=technique_id,
                        description=self.__clean_description(rel_description),
                        domain=self.domain,
                        reference_list=self.__create_reference_list(rel_description),
                        stix_id=rel["id"],
                    ),
                )
            mitigation_list.append(
                AttackAbstractMitigation(
                    name=obj["name"],
                    mitigation_id=mitigation_id,
                    description=self.__clean_description(description),
                    domain=self.domain,
                    concrete_mitigation_list=concrete_mitigation_list,
                    reference_list=self.__create_reference_list(description),
                    stix_id=obj["id"],
                ),
            )
        return mitigation_list

    def __target_attack_id(self, rel: dict[str, Any]) -> str:
        return attack_id_of(self._bundle.objects_by_id[rel["target_ref"]]) or ""

    def __create_procedure_list(self, obj: dict[str, Any]) -> list[AttackProcedure]:
        """1つのGroup / Software / Campaign が技術を使用する uses relationship からプロシージャを作成する。"""
        if not hasattr(self, "_technique_uses_by_source"):
            self._technique_uses_by_source: dict[str, list[dict[str, Any]]] = {}
            for rel in self._bundle.relationships_of("uses"):
                if rel["target_ref"].startswith("attack-pattern--"):
                    self._technique_uses_by_source.setdefault(rel["source_ref"], []).append(rel)
        parent_id = attack_id_of(obj) or ""
        procedure_list: list[AttackProcedure] = []
        for rel in sorted(self._technique_uses_by_source.get(obj["id"], []), key=self.__target_attack_id):
            technique_id = self.__target_attack_id(rel)
            if not technique_id:
                continue
            self.procedure_count += 1
            rel_description: str = rel.get("description", "")
            procedure_list.append(
                AttackProcedure(
                    original_id=f"P{str(self.procedure_count).zfill(4)}",
                    parent_id=parent_id,
                    parent_name=obj["name"],
                    parent_type=_PROCEDURE_PARENT_TYPES[obj["type"]],
                    technique_id=technique_id,
                    description=self.__clean_description(rel_description),
                    domain=self.domain,
                    reference_list=self.__create_reference_list(rel_description),
                    stix_id=rel["id"],
                ),
            )
        return procedure_list

    def __setup_campaign_list(self) -> list[AttackCampaign]:
        return [
            AttackCampaign(
                name=obj["name"],
                campaign_id=attack_id_of(obj) or "",
                description=self.__clean_description(obj.get("description", "")),
                domain=self.domain,
                procedure_list=self.__create_procedure_list(obj),
                reference_list=self.__create_reference_list(obj.get("description", "")),
                stix_id=obj["id"],
                aliases=[a for a in obj.get("aliases", []) if a != obj["name"]],
                url=attack_url_of(obj),
                first_seen=obj.get("first_seen"),
                last_seen=obj.get("last_seen"),
            )
            for obj in self._bundle.of_type("campaign")
        ]

    def __setup_software_list(self) -> list[AttackSoftware]:
        return [
            AttackSoftware(
                name=obj["name"],
                software_id=attack_id_of(obj) or "",
                description=self.__clean_description(obj.get("description", "")),
                domain=self.domain,
                procedure_list=self.__create_procedure_list(obj),
                reference_list=self.__create_reference_list(obj.get("description", "")),
                stix_id=obj["id"],
                aliases=[a for a in obj.get("x_mitre_aliases", []) if a != obj["name"]],
                url=attack_url_of(obj),
                software_type=obj["type"],
                platforms=obj.get("x_mitre_platforms"),
            )
            for obj in self._bundle.of_type("malware", "tool")
        ]

    def __setup_group_list(self) -> list[AttackGroup]:
        return [
            AttackGroup(
                name=obj["name"],
                group_id=attack_id_of(obj) or "",
                description=self.__clean_description(obj.get("description", "")),
                domain=self.domain,
                procedure_list=self.__create_procedure_list(obj),
                reference_list=self.__create_reference_list(obj.get("description", "")),
                stix_id=obj["id"],
                aliases=[a for a in obj.get("aliases", []) if a != obj["name"]],
                url=attack_url_of(obj),
            )
            for obj in self._bundle.of_type("intrusion-set")
        ]

    def __setup_relationships(self) -> list[AttackRelationship]:
        """両端がATT&CK IDを持つ有効なrelationshipを AttackRelationship に変換する。"""
        relationships: list[AttackRelationship] = []
        for rel in self._bundle.relationships:
            source = self._bundle.objects_by_id[rel["source_ref"]]
            target = self._bundle.objects_by_id[rel["target_ref"]]
            source_id, target_id = attack_id_of(source), attack_id_of(target)
            if source_id is None or target_id is None:
                continue
            relationships.append(
                AttackRelationship(
                    source_id=source_id,
                    target_id=target_id,
                    type=rel["relationship_type"],
                    description=rel.get("description"),
                    stix_id=rel["id"],
                    source_type=source["type"],
                    target_type=target["type"],
                    raw=rel,
                ),
            )
        return relationships

    def __link_entities(self) -> None:
        """relationshipをもとにオブジェクト間の参照 (サブテクニック、緩和策、プロシージャ等) を設定する。"""
        techniques = {t.id: t for t in self.technique_list}
        for mitigation in self.mitigation_list:
            for concrete in mitigation.concrete_mitigation_list:
                if concrete.technique_id in techniques:
                    techniques[concrete.technique_id].mitigation_list.append(concrete)
        for parent in [*self.campaign_list, *self.group_list, *self.software_list]:
            for procedure in parent.procedure_list:
                if procedure.technique_id in techniques:
                    techniques[procedure.technique_id].procedure_list.append(procedure)
        self.__link_relationship_references(techniques)

    def __link_relationship_references(self, techniques: dict[str, AttackTechnique]) -> None:
        """subtechnique-of / attributed-to / uses(→Software) をオブジェクト間の参照に反映する。"""
        groups = {g.id: g for g in self.group_list}
        software = {s.id: s for s in self.software_list}
        campaigns = {c.id: c for c in self.campaign_list}
        for rel in self.relationships:
            if rel.type == "subtechnique-of" and rel.source_id in techniques and rel.target_id in techniques:
                child, parent_tec = techniques[rel.source_id], techniques[rel.target_id]
                child.have_parent, child.parent_id, child.parent = True, parent_tec.id, parent_tec
                parent_tec.subtechnique_list.append(child)
            elif rel.type == "attributed-to" and rel.source_id in campaigns and rel.target_id in groups:
                campaigns[rel.source_id].group_list.append(groups[rel.target_id])
                groups[rel.target_id].campaign_list.append(campaigns[rel.source_id])
            elif rel.type == "uses" and rel.target_id in software:
                sw = software[rel.target_id]
                if rel.source_id in groups:
                    groups[rel.source_id].software_list.append(sw)
                    sw.group_list.append(groups[rel.source_id])
                elif rel.source_id in campaigns:
                    campaigns[rel.source_id].software_list.append(sw)
                    sw.campaign_list.append(campaigns[rel.source_id])

    def get_relationships(
        self,
        *,
        source_id: str | None = None,
        target_id: str | None = None,
        type: str | None = None,  # noqa: A002
    ) -> list[AttackRelationship]:
        """
        relationshipを起点ID・対象ID・種別で絞り込んで返す。

        Args:
            source_id (str | None): 起点のATT&CK ID (例: "G0007")
            target_id (str | None): 対象のATT&CK ID (例: "T1059.001")
            type (str | None): 関係種別 (例: "uses", "mitigates", "subtechnique-of", "attributed-to")

        Returns:
            list[AttackRelationship]: 条件に一致するrelationship
        """
        return [
            rel
            for rel in self.relationships
            if (source_id is None or rel.source_id == source_id)
            and (target_id is None or rel.target_id == target_id)
            and (type is None or rel.type == type)
        ]

    def __initialize_vector(self) -> None:
        try:
            self.__initialize_technique_vector()
            self.__initialize_procedure_vector()
            print("ベクトルDBの初期化が完了しました。")  # 初期化完了のメッセージ
        except Exception:
            shutil.rmtree(self.chroma_path)
            raise

    def __initialize_technique_vector(self) -> None:
        # ベクトルdb(chroma)とavroファイルの両方を初期化する関数
        # ベクトルavroファイルの初期化
        id_list: list[str] = []
        desc_list: list[str] = []
        metadata_list: list[dict[str, bool]] = []  # {"is_parent":bool}の形を保持した辞書
        for tec in self.technique_list:
            id_list.append(tec.id)
            desc_list.append(tec.description)
            metadata_list.append({"is_parent": not tec.have_parent})
        # ベクトルDB(chroma)の初期化
        with suppress(NotFoundError):
            self.chroma_client.delete_collection(name="attack_technique")  # 存在する場合は一度削除してリセット
        collection: Collection = self.chroma_client.get_or_create_collection(
            name="attack_technique",
            metadata={"hnsw:space": "cosine"},
            embedding_function=self._embedding_function,  # ty:ignore[invalid-argument-type]
        )
        print("テクニックベクトルDB初期化中...")
        for i in tqdm(range(0, len(id_list), 200)):  # rate limitを避けるため200件ずつ追加
            end_idx = min(i + 200, len(id_list))
            collection.add(
                documents=desc_list[i:end_idx],
                ids=id_list[i:end_idx],
                metadatas=metadata_list[i:end_idx],  # ty:ignore[invalid-argument-type]
            )

    def __initialize_procedure_vector(self) -> None:
        # procedureについてベクトルDB(chroma)とavroファイルの両方を初期化する関数
        id_list: list[str] = []
        desc_list: list[str] = []
        metadata_list: list[dict[str, str]] = []  # {"parent": "campaign"}等の形を保持した辞書
        for campaign in self.campaign_list:
            for proc in campaign.procedure_list:
                id_list.append(proc.original_id)
                desc_list.append(proc.description)
                metadata_list.append({"parent": "campaign"})
        for group in self.group_list:
            for proc in group.procedure_list:
                id_list.append(proc.original_id)
                desc_list.append(proc.description)
                metadata_list.append({"parent": "group"})
        for software in self.software_list:
            for proc in software.procedure_list:
                id_list.append(proc.original_id)
                desc_list.append(proc.description)
                metadata_list.append({"parent": "software"})
        # ベクトルDB(chroma)の初期化
        with suppress(NotFoundError):
            self.chroma_client.delete_collection(name="attack_procedure")  # 存在する場合は一度削除してリセット
        collection: Collection = self.chroma_client.get_or_create_collection(
            name="attack_procedure",
            metadata={"hnsw:space": "cosine"},
            embedding_function=self._embedding_function,  # ty:ignore[invalid-argument-type]
        )
        print("プロシージャベクトルDB初期化中...")
        for i in tqdm(range(0, len(id_list), 200)):  # rate limitを避けるため200件ずつ追加
            end_idx = min(i + 200, len(id_list))
            collection.add(
                documents=desc_list[i:end_idx],
                ids=id_list[i:end_idx],
                metadatas=metadata_list[i:end_idx],  # ty:ignore[invalid-argument-type]
            )

    def __get_technique_chroma_collection(self) -> Collection:  # chromaDBを起動する関数
        collection: Collection = self.chroma_client.get_collection(name="attack_technique", embedding_function=self._embedding_function)  # ty:ignore[invalid-argument-type]
        return collection

    def __get_procedure_chroma_collection(self) -> Collection:  # chromaDBを起動する関数
        collection: Collection = self.chroma_client.get_collection(name="attack_procedure", embedding_function=self._embedding_function)  # ty:ignore[invalid-argument-type]
        return collection

    def __create_reference_list(self, desc: str) -> list[AttackExternalReference | AttackInternalReference]:
        """
        referenceオブジェクトのリストをdescから各テクニック、緩和策ごとに作成する
        """
        ret_list: list[AttackExternalReference | AttackInternalReference] = []
        ref_list: list[str] = list(dict.fromkeys(re.findall(r"\(Citation: (.*?)\)|\[.*?\]\((https://attack.mitre.org/.*?)\)", desc)))
        for match_tuple in ref_list:
            if match_tuple[0] != "":  # 外部参照の場合
                # 外部参照リストに存在しない引用名(ICSデータの "N/A" など)はスキップする
                try:
                    ref: AttackExternalReference = self.get_external_reference_by_name(match_tuple[0])
                except ValueError:
                    continue
                ret_list.append(ref)
            elif match_tuple[1] != "":  # 内部参照の場合
                id_match = re.search(r"([A-Z]+\d{4,6}.*)", match_tuple[1])
                if id_match:
                    mitre_id: str = id_match.group(1).replace("/", ".")
                    internal_ref = AttackInternalReference(
                        mitre_id=mitre_id,
                        url=match_tuple[1],
                    )
                    ret_list.append(internal_ref)
        return ret_list

    def __clean_description(self, desc: str) -> str:
        """
        descから引用を引用マーク([0], [1]など)に順番に変換する
        同じ引用には同じ番号を割り当てる
        """
        external_pattern = r"\(Citation: .*?\)"
        internal_pattern = r"\[.*?\]\(https://attack.mitre.org/.*?\)"
        combined_pattern = f"{external_pattern}|{internal_pattern}"

        ref_to_number: dict[str, int] = {}  # 引用文字列 -> 番号のマッピング
        counter = 0

        def replace_with_counter(match: re.Match[str]) -> str:
            nonlocal counter
            matched_text = match.group()
            if matched_text not in ref_to_number:
                ref_to_number[matched_text] = counter
                counter += 1
            return f"[{ref_to_number[matched_text]}]"

        result: str = re.sub(combined_pattern, replace_with_counter, desc)
        return result

    def get_tactic_by_id(self, tactic_id: str) -> AttackTactic:
        """
        idからタクティックオブジェクトを取得する

        Args:
            tactic_id (str): タクティックID (例: TA0001)

        Returns:
            AttackTactic: タクティックオブジェクト

        Raises:
            ValueError: 指定したIDのタクティックが存在しない場合
        """
        for tactic in self.tactic_list:
            if tactic.id == tactic_id:
                return tactic
        err_msg = f"tactic_id: {tactic_id} は存在しません"
        raise ValueError(err_msg)

    def get_procedure_by_technique_id(self, technique_id: str) -> list[AttackProcedure]:
        """
        1つのテクニックに紐づくCampaign・Group・Software中のProcedureオブジェクトを取得する

        Args:
            technique_id (str): テクニックID (例: T1059.001)

        Returns:
            list[AttackProcedure]: Procedureのリスト

        Raises:
            ValueError: 指定したIDのテクニックが存在しない場合
        """
        procedure_list: list[AttackProcedure] = []
        for campaign in self.campaign_list:
            for procedure in campaign.procedure_list:
                if procedure.technique_id == technique_id:
                    procedure_list.append(procedure)  # noqa: PERF401
        for group in self.group_list:
            for procedure in group.procedure_list:
                if procedure.technique_id == technique_id:
                    procedure_list.append(procedure)  # noqa: PERF401
        for software in self.software_list:
            for procedure in software.procedure_list:
                if procedure.technique_id == technique_id:
                    procedure_list.append(procedure)  # noqa: PERF401
        return procedure_list

    def get_concrete_mitigation_by_technique_id(self, technique_id: str) -> list[AttackConcreteMitigation]:
        """
        テクニックidからConcreteMitigationオブジェクトを取得する

        Args:
            technique_id (str): テクニックID (例: T1059.001)

        Returns:
            list[AttackConcreteMitigation]: 具体緩和策のリスト

        Raises:
            ValueError: 指定したIDの具体緩和策が存在しない場合
        """
        concrete_mitigation_list: list[AttackConcreteMitigation] = []
        for abstract_mitigation in self.mitigation_list:
            for concrete_mitigation in abstract_mitigation.concrete_mitigation_list:
                if concrete_mitigation.technique_id == technique_id:
                    concrete_mitigation_list.append(concrete_mitigation)  # noqa: PERF401
        return concrete_mitigation_list

    def get_tactic_by_name(self, tactic_name: str) -> AttackTactic:
        """
        タクティック名からタクティックオブジェクトを取得する

        Args:
            tactic_name (str): タクティック名 (例: Initial Access)

        Returns:
            AttackTactic: タクティックオブジェクト

        Raises:
            ValueError: 指定した名前のタクティックが存在しない場合
        """
        for tactic in self.tactic_list:
            if tactic.name == tactic_name:
                return tactic
        err_msg = f"tactic_name: {tactic_name} は存在しません"
        raise ValueError(err_msg)

    def get_mitigation_by_id(self, mitigation_id: str) -> AttackAbstractMitigation:
        """
        緩和策idから緩和策オブジェクトを取得する

        Args:
            mitigation_id (str): 緩和策ID (例: M1010)

        Returns:
            AttackAbstractMitigation: 緩和策オブジェクト

        Raises:
            ValueError: 指定したIDの緩和策が存在しない場合
        """
        for mitigation in self.mitigation_list:
            if mitigation.id == mitigation_id:
                return mitigation
        err_msg = f"mitigation_id: {mitigation_id} は存在しません"
        raise ValueError(err_msg)

    def get_external_reference_by_name(self, name: str) -> AttackExternalReference:
        """
        外部参照の引用名から外部参照オブジェクトを取得する

        Args:
            name (str): 引用名 (例: ADSecurity Kerberos and KRBTGT)

        Returns:
            AttackExternalReference: 外部参照オブジェクト

        Raises:
            ValueError: 指定した名前の外部参照が存在しない場合
        """
        for ref in self.external_reference_list:
            if ref.name == name:
                return ref
        err_msg = f"外部参考資料: {name} は存在しません"
        raise ValueError(err_msg)

    def get_technique_by_id(self, technique_id: str) -> AttackTechnique:
        """
        テクニックidからテクニックオブジェクトを取得する

        Args:
            technique_id (str): テクニックID (例: T1059.001)

        Returns:
            AttackTechnique: テクニックオブジェクト

        Raises:
            ValueError: 指定したIDのテクニックが存在しない場合
        """
        for tec in self.technique_list:
            if tec.id == technique_id:
                return tec
        err_msg = f"technique_id: {technique_id} は存在しません"
        raise ValueError(err_msg)

    def get_software_by_id(self, software_id: str) -> AttackSoftware:
        """
        ソフトウェアidからソフトウェアオブジェクトを取得する

        Args:
            software_id (str): ソフトウェアID (例: S0001)

        Returns:
            AttackSoftware: ソフトウェアオブジェクト

        Raises:
            ValueError: 指定したIDのソフトウェアが存在しない場合
        """
        for software in self.software_list:
            if software.id == software_id:
                return software
        err_msg = f"software_id: {software_id} は存在しません"
        raise ValueError(err_msg)

    def get_group_by_id(self, group_id: str) -> AttackGroup:
        """
        グループidからグループオブジェクトを取得する

        Args:
            group_id (str): グループID (例: G0001)

        Returns:
            AttackGroup: グループオブジェクト

        Raises:
            ValueError: 指定したIDのグループが存在しない場合
        """
        for group in self.group_list:
            if group.id == group_id:
                return group
        err_msg = f"group_id: {group_id} は存在しません"
        raise ValueError(err_msg)

    def get_campaign_by_id(self, campaign_id: str) -> AttackCampaign:
        """
        キャンペーンidからキャンペーンオブジェクトを取得する

        Args:
            campaign_id (str): キャンペーンID (例: C0001)

        Returns:
            AttackCampaign: キャンペーンオブジェクト

        Raises:
            ValueError: 指定したIDのキャンペーンが存在しない場合
        """
        for campaign in self.campaign_list:
            if campaign.id == campaign_id:
                return campaign
        err_msg = f"campaign_id: {campaign_id} は存在しません"
        raise ValueError(err_msg)

    def get_procedure_by_id(self, procedure_id: str) -> AttackProcedure:
        """
        親IDとテクニックIDからプロシージャオブジェクトを取得する

        Args:
            procedure_id (str): プロシージャID (例: P0001)

        Returns:
            AttackProcedure: プロシージャオブジェクト

        Raises:
            ValueError: 指定したIDのプロシージャが存在しない場合
        """
        for campaign in self.campaign_list:
            for procedure in campaign.procedure_list:
                if procedure.original_id == procedure_id:
                    return procedure
        for group in self.group_list:
            for procedure in group.procedure_list:
                if procedure.original_id == procedure_id:
                    return procedure
        for software in self.software_list:
            for procedure in software.procedure_list:
                if procedure.original_id == procedure_id:
                    return procedure
        err_msg = f"procedure_id: {procedure_id} は存在しません"
        raise ValueError(err_msg)

    def search_relevant_techniques(
        self,
        query: str,
        top_k: int,
        *,
        filter: Literal["parent", "child", "both"] = "both",  # noqa: A002
    ) -> list[AttackTechnique]:
        """
        クエリを元にベクトルDBを検索する関数

        Args:
            query (str): 検索文言
            top_k (int): 上位何件を取得するか
            filter (str): 親のみ, 子のみ, 両方 の3種類でフィルターをかける

        Returns:
            list[AttackTechnique]: top_kで指定された個数分上位の結果をテクニックオブジェクト
        """
        if self.technique_chroma_collection is None:
            err_msg = "選択したEmbedding providerの設定がないため、ベクトルDB検索は無効化されています。"
            raise ValueError(err_msg)
        if filter == "parent":
            result = self.technique_chroma_collection.query(query_texts=[query], n_results=top_k, where={"is_parent": True})
        elif filter == "child":
            result = self.technique_chroma_collection.query(query_texts=[query], n_results=top_k, where={"is_parent": False})
        elif filter == "both":
            result = self.technique_chroma_collection.query(query_texts=[query], n_results=top_k)
        ret: list[AttackTechnique] = [self.get_technique_by_id(technique_id=tec_id) for tec_id in result["ids"][0]]
        return ret

    def search_relevant_procedures(
        self,
        query: str,
        top_k: int,
        *,
        filter: Literal["campaign", "group", "software", "all"] = "all",  # noqa: A002
    ) -> list[AttackProcedure]:
        """
        クエリを元にベクトルDBを検索する関数

        Args:
            query (str): 検索文言
            top_k (int): 上位何件を取得するか
            filter (str): campaign, group, software, all のどれorすべてから取得するか
        Returns:
            list[AttackProcedure]: top_kで指定された個数分上位の結果をプロシージャオブジェクト
        """
        if self.procedure_chroma_collection is None:
            err_msg = "選択したEmbedding providerの設定がないため、ベクトルDB検索は無効化されています。"
            raise ValueError(err_msg)
        result = self.procedure_chroma_collection.query(query_texts=[query], n_results=top_k, where={"parent": filter} if filter != "all" else None)
        ret: list[AttackProcedure] = [self.get_procedure_by_id(procedure_id=proc_id) for proc_id in result["ids"][0]]
        return ret

    def get_available_versions(self) -> list[str]:
        """
        利用可能なATLASのバージョン一覧を取得する関数

        Returns:
            list[str]: 利用可能なATTACKのバージョン一覧
        """
        return version_resolver.list_versions()

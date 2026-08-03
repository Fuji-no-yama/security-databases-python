import re
import shutil
from contextlib import suppress
from importlib.resources import files
from pathlib import Path
from typing import Literal

import chromadb
import pandas as pd
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
    AttackSoftware,
    AttackTactic,
    AttackTechnique,
)


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
        self.version = f"v{resolved_version}"  # ディレクトリ名はv17.1のような形式であるため、バージョンをv{version}の形式に変換
        self.data_dir_path = files("attack.data").joinpath(data_path)  # パッケージ内のdataディレクトリ
        self.user_data_dir_path: Path = Path(user_data_dir("attack")) / "releases" / resolved_version / domain
        self.user_data_dir_path.mkdir(parents=True, exist_ok=True)  # 念の為作成
        self.external_reference_list: list[AttackExternalReference] = self.__setup_external_reference_list()
        self.tactic_list: list[AttackTactic] = self.__setup_tactic_list()
        self.mitigation_list: list[AttackAbstractMitigation] = self.__setup_mitigation_list()
        self.campaign_list: list[AttackCampaign] = self.__setup_campaign_list()
        self.group_list: list[AttackGroup] = self.__setup_group_list()
        self.software_list: list[AttackSoftware] = self.__setup_software_list()
        self.technique_list: list[AttackTechnique] = self.__setup_technique_list()

        self.technique_chroma_collection: Collection | None = None
        self.procedure_chroma_collection: Collection | None = None

        embedding_configuration = resolve_embedding_configuration(embedding_provider, emb_model)
        if embedding_configuration is not None:
            self._embedding_function = create_embedding_function(embedding_configuration)
            self.chroma_path = self.user_data_dir_path / "chroma" / embedding_configuration.cache_key
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
        mitigation_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-mitigations.xlsx",
            sheet_name="citations",
        )
        technique_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-techniques.xlsx",
            sheet_name="citations",
        )
        campaign_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-campaigns.xlsx",
            sheet_name="citations",
        )
        group_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-groups.xlsx",
            sheet_name="citations",
        )
        software_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-software.xlsx",
            sheet_name="citations",
        )
        reference_df: pd.DataFrame = (
            pd.concat([mitigation_df, technique_df, campaign_df, group_df, software_df]).drop_duplicates().reset_index(drop=True)
        )
        ret_list: list[AttackExternalReference] = []
        for i, (_, row) in enumerate(reference_df.iterrows()):
            ref = AttackExternalReference(
                reference_id=i,
                name=row["reference"],
                url=row["url"],
                description=row["citation"],
            )
            ret_list.append(ref)
        return ret_list

    def __setup_tactic_list(self) -> list[AttackTactic]:
        tactic_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-tactics.xlsx",
            sheet_name="tactics",
        )
        tactic_list: list[AttackTactic] = []
        for _, row in tactic_df.iterrows():
            tactic_id: str = row["ID"]
            name: str = row["name"]
            description: str = row["description"]
            tactic = AttackTactic(
                tactic_id=tactic_id,
                name=name,
                domain=self.domain,
                description=description,
                technique_list=[],
            )
            tactic_list.append(tactic)
        return tactic_list

    def __setup_mitigation_list(self) -> list[AttackAbstractMitigation]:
        abstract_mitigation_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-mitigations.xlsx",
            sheet_name="mitigations",
        )
        concrete_mitigation_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-mitigations.xlsx",
            sheet_name="techniques addressed",
        )
        mitigation_list: list[AttackAbstractMitigation] = []
        for _, row in abstract_mitigation_df.iterrows():
            mitigation_id: str = row["ID"]
            description: str = row["description"]
            concrete_mitigation_list: list[AttackConcreteMitigation] = []
            for _, conc_mit_row in concrete_mitigation_df[concrete_mitigation_df["source ID"] == mitigation_id].iterrows():
                conc_mit = AttackConcreteMitigation(
                    abstract_mitigation_id=mitigation_id,
                    abstract_mitigation_name=row["name"],
                    technique_id=conc_mit_row["target ID"],
                    description=self.__clean_description(conc_mit_row["mapping description"]),
                    domain=self.domain,
                    reference_list=self.__create_reference_list(conc_mit_row["mapping description"]),
                )
                concrete_mitigation_list.append(conc_mit)
            mitigation = AttackAbstractMitigation(
                name=row["name"],
                mitigation_id=mitigation_id,
                description=self.__clean_description(description),
                domain=self.domain,
                concrete_mitigation_list=concrete_mitigation_list,
                reference_list=self.__create_reference_list(description),
            )
            mitigation_list.append(mitigation)
        return mitigation_list

    def __setup_campaign_list(self) -> list[AttackCampaign]:
        campaign_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-campaigns.xlsx",
            sheet_name="campaigns",
        )
        procedure_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-campaigns.xlsx",
            sheet_name="techniques used",
        )
        campaign_list: list[AttackCampaign] = []
        for _, row in campaign_df.iterrows():
            campaign_id = row["ID"]
            associated_procedure_df = procedure_df[procedure_df["source ID"] == campaign_id]
            procedure_list: list[AttackProcedure] = []
            for _, proc_row in associated_procedure_df.iterrows():
                procedure = AttackProcedure(
                    original_id=f"P{str(self.procedure_count + 1).zfill(4)}",
                    parent_id=campaign_id,
                    parent_name=row["name"],
                    parent_type="campaign",
                    technique_id=proc_row["target ID"],
                    description=self.__clean_description(proc_row["mapping description"]),
                    domain=self.domain,
                    reference_list=self.__create_reference_list(proc_row["mapping description"]),
                )
                procedure_list.append(procedure)
                self.procedure_count += 1
            campaign = AttackCampaign(
                name=row["name"],
                campaign_id=campaign_id,
                description=self.__clean_description(row["description"]),
                domain=self.domain,
                procedure_list=procedure_list,
                reference_list=self.__create_reference_list(row["description"]),
            )
            campaign_list.append(campaign)
        return campaign_list

    def __setup_software_list(self) -> list[AttackSoftware]:
        software_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-software.xlsx",
            sheet_name="software",
        )
        procedure_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-software.xlsx",
            sheet_name="techniques used",
        )
        software_list: list[AttackSoftware] = []
        for _, row in software_df.iterrows():
            software_id = row["ID"]
            associated_procedure_df = procedure_df[procedure_df["source ID"] == software_id]
            procedure_list: list[AttackProcedure] = []
            for _, proc_row in associated_procedure_df.iterrows():
                procedure = AttackProcedure(
                    original_id=f"P{str(self.procedure_count + 1).zfill(4)}",
                    parent_id=software_id,
                    parent_name=row["name"],
                    parent_type="software",
                    technique_id=proc_row["target ID"],
                    description=self.__clean_description(proc_row["mapping description"]),
                    domain=self.domain,
                    reference_list=self.__create_reference_list(proc_row["mapping description"]),
                )
                self.procedure_count += 1
                procedure_list.append(procedure)
            software = AttackSoftware(
                name=row["name"],
                software_id=software_id,
                description=self.__clean_description(row["description"]),
                domain=self.domain,
                procedure_list=procedure_list,
                reference_list=self.__create_reference_list(row["description"]),
            )
            software_list.append(software)
        return software_list

    def __setup_group_list(self) -> list[AttackGroup]:
        group_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-groups.xlsx",
            sheet_name="groups",
        )
        procedure_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-groups.xlsx",
            sheet_name="techniques used",
        )
        group_list: list[AttackGroup] = []
        for _, row in group_df.iterrows():
            group_id = row["ID"]
            associated_procedure_df = procedure_df[procedure_df["source ID"] == group_id]
            procedure_list: list[AttackProcedure] = []
            for _, proc_row in associated_procedure_df.iterrows():
                procedure = AttackProcedure(
                    original_id=f"P{str(self.procedure_count + 1).zfill(4)}",
                    parent_id=group_id,
                    parent_name=row["name"],
                    parent_type="group",
                    technique_id=proc_row["target ID"],
                    description=self.__clean_description(proc_row["mapping description"]),
                    domain=self.domain,
                    reference_list=self.__create_reference_list(proc_row["mapping description"]),
                )
                self.procedure_count += 1
                procedure_list.append(procedure)
            group = AttackGroup(
                name=row["name"],
                group_id=group_id,
                description=self.__clean_description(row["description"]),
                domain=self.domain,
                procedure_list=procedure_list,
                reference_list=self.__create_reference_list(row["description"]),
            )
            group_list.append(group)
        return group_list

    def __setup_technique_list(self) -> list[AttackTechnique]:
        tech_df: pd.DataFrame = pd.read_excel(
            self.data_dir_path / f"{self.domain}-attack-{self.version}-techniques.xlsx",
            sheet_name="techniques",
        )
        technique_list: list[AttackTechnique] = []
        for _, row in tech_df.iterrows():
            tec_id: str = row["ID"]
            tactic_list: list[AttackTactic] = [self.get_tactic_by_name(n) for n in row["tactics"].split(", ")]
            parent_id: str | None = (
                re.findall(r"(T\d{4})\.\d{3}", tec_id)[0] if re.search(r"T\d{4}\.\d{3}", tec_id) else None
            )  # サブテクニック(例: T1548.002)の場合、親ID(例: T1548)を抽出
            tec = AttackTechnique(
                name=row["name"],
                technique_id=tec_id,
                description=self.__clean_description(row["description"]),
                domain=self.domain,
                mitigation_list=self.get_concrete_mitigation_by_technique_id(technique_id=tec_id),
                procedure_list=self.get_procedure_by_technique_id(technique_id=tec_id),
                have_parent=bool(parent_id),
                parent_id=parent_id,
                tactics=tactic_list if row["ID"] != "" else [],
                reference_list=self.__create_reference_list(row["description"]),
            )
            technique_list.append(tec)
            for tactic in tactic_list:  # タクティックにテクニックを追加
                self.__add_technique_to_tactic(tactic.name, tec)
        return technique_list

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

    def __add_technique_to_tactic(
        self,
        tactic_name: str,
        technique: AttackTechnique,
    ) -> None:
        """
        タクティックにテクニックを追加する
        """
        tactic = self.get_tactic_by_name(tactic_name)
        if tactic is not None:
            tactic.technique_list.append(technique)
        else:
            err_msg = f"tactic_name: {tactic_name} は存在しません"
            raise ValueError(err_msg)

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

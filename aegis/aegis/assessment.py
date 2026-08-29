from pathlib import Path

from aegis.context import CampaignContext
from aegis.result_store import ResultStore
from aegis.scope_manager import ScopeManager
from aegis.asset_store import AssetStore
from aegis.observation_processor import (
    ObservationProcessor,
)
from aegis.integrity_store import IntegrityStore
from aegis.relation_store import RelationStore
from aegis.change_store import ChangeStore


class AssessmentContext:
    def __init__(
        self,
        campaign: CampaignContext,
    ):
        self.campaign = campaign

        self.scope = ScopeManager(
            campaign.scope_file
        )

        self.results = ResultStore(
            campaign.data_dir / "results"
        )

        self.assets = AssetStore(
            campaign.data_dir / "assets"
        )

        self.integrity = IntegrityStore(
            campaign.data_dir / "integrity"
        )

        self.relations = RelationStore(
            campaign.data_dir / "relations"
        )

        self.changes = ChangeStore(
            campaign.data_dir / "changes"
        )

        self.observation_processor = (
            ObservationProcessor(
                asset_store=self.assets,
                scope=self.scope.engine,
                relation_store=self.relations,
            )
        )

    @property
    def root(self) -> Path:
        return self.campaign.path

    @property
    def data_dir(self) -> Path:
        return self.campaign.data_dir

    @property
    def evidence_dir(self) -> Path:
        return self.campaign.evidence_dir

    @property
    def reports_dir(self) -> Path:
        return self.campaign.reports_dir

    @property
    def results_dir(self) -> Path:
        return (
            self.campaign.data_dir
            / "results"
        )

    @property
    def assets_dir(self) -> Path:
        return (
            self.campaign.data_dir
            / "assets"
        )

    @property
    def relations_dir(self) -> Path:
        return (
            self.campaign.data_dir
            / "relations"
        )

    @property
    def changes_dir(self) -> Path:
        return (
            self.campaign.data_dir
            / "changes"
        )
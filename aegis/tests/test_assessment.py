from pathlib import Path

from aegis.assessment import AssessmentContext
from aegis.context import CampaignContext

def test_assessment_context(tmp_path: Path):
    campaign = tmp_path / "campaign"

    campaign.mkdir()
    (campaign / "data").mkdir()
    (campaign / "evidence").mkdir()
    (campaign / "reports").mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    context = AssessmentContext(
        CampaignContext(campaign)
    )

    assert context.root == campaign
    assert context.data_dir == campaign / "data"
    assert context.evidence_dir == campaign / "evidence"
    assert context.reports_dir == campaign / "reports"

def test_assessment_context_scope(tmp_path: Path):
    campaign = tmp_path / "campaign"

    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    context = AssessmentContext(
        CampaignContext(campaign)
    )

    context.scope.add("example.com")

    targets = context.scope.list()

    assert len(targets) == 1
    assert targets[0].value == "example.com"

def test_assessment_context_results(tmp_path):
    campaign = tmp_path / "campaign"

    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    context = AssessmentContext(
        CampaignContext(campaign)
    )

    assert context.results_dir == (
        campaign / "data" / "results"
    )

    assert context.results.directory == (
        campaign / "data" / "results"
    )

def test_assessment_context_can_save_result(tmp_path):
    from aegis.results import PluginResult

    campaign = tmp_path / "campaign"

    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    context = AssessmentContext(
        CampaignContext(campaign)
    )

    result = PluginResult(
        plugin="test",
        version="0.1.0",
    )

    path = context.results.save(result)

    assert path.exists()
    assert path.parent == (
        campaign / "data" / "results"
    )

def test_assessment_context_assets(tmp_path):
    campaign = tmp_path / "campaign"

    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    context = AssessmentContext(
        CampaignContext(campaign)
    )

    assert context.assets_dir == (
        campaign / "data" / "assets"
    )

    assert context.assets.directory == (
        campaign / "data" / "assets"
    )

def test_assessment_context_can_save_asset(tmp_path):
    from aegis.models import Asset, AssetType

    campaign = tmp_path / "campaign"

    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    context = AssessmentContext(
        CampaignContext(campaign)
    )

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    path = context.assets.save(asset)

    assert path.exists()
    assert path.parent == (
        campaign / "data" / "assets"
    )

def test_assessment_context_has_observation_processor(
    tmp_path,
):
    campaign = tmp_path / "campaign"
    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    context = AssessmentContext(
        CampaignContext(campaign)
    )

    assert context.observation_processor is not None
    assert (
        context.observation_processor.asset_store
        is context.assets
    )
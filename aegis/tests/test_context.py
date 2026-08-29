from pathlib import Path

from aegis.context import CampaignContext, find_campaign

def test_campaign_context(tmp_path: Path):
    campaign = tmp_path / "teste"
    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: teste\n",
        encoding="utf-8",
    )

    context = CampaignContext(campaign)

    assert context.config_file == campaign / "aegis.yaml"
    assert context.scope_file == campaign / "scope.yaml"
    assert context.data_dir == campaign / "data"
    assert context.evidence_dir == campaign / "evidence"
    assert context.reports_dir == campaign / "reports"

    assert context.is_valid()

def test_find_campaign_from_subdirectory(tmp_path: Path):
    campaign = tmp_path / "teste"
    nested = campaign / "data"

    campaign.mkdir()
    nested.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: teste\n",
        encoding="utf-8",
    )

    context = find_campaign(nested)

    assert context is not None
    assert context.path == campaign

def test_find_campaign_returns_none(tmp_path: Path):
    context = find_campaign(tmp_path)

    assert context is None
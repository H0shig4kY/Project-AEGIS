from aegis.plugins.base import Plugin
from aegis.plugins.manager import PluginManager

class TestPlugin(Plugin):
    name = "test"
    version = "0.1.0"
    description = "Test plugin"

    def execute(self, context):
        return {
        "status": "success",
        "scope_count": len(context.scope.list()),
    }

def test_register_plugin():
    manager = PluginManager()

    plugin = TestPlugin()

    manager.register(plugin)

    assert manager.get("test") is plugin

def test_list_plugins():
    manager = PluginManager()

    manager.register(TestPlugin())

    plugins = manager.list()

    assert len(plugins) == 1
    assert plugins[0].name == "test"

def test_duplicate_plugin_is_rejected():
    manager = PluginManager()

    manager.register(TestPlugin())

    try:
        manager.register(TestPlugin())
        assert False
    except ValueError:
        assert True

def test_remove_plugin():
    manager = PluginManager()

    manager.register(TestPlugin())

    assert manager.remove("test") is True
    assert manager.get("test") is None

def test_remove_unknown_plugin():
    manager = PluginManager()

    assert manager.remove("unknown") is False

def test_plugin_receives_assessment_context(tmp_path):
    from aegis.assessment import AssessmentContext
    from aegis.context import CampaignContext

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

    plugin = TestPlugin()

    result = plugin.execute(context)

    assert result["status"] == "success"
    assert result["scope_count"] == 1
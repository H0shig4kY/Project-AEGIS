from aegis.plugins.registry import create_plugin_manager

def test_builtin_plugins_are_registered():
    manager = create_plugin_manager()

    plugin = manager.get("dns")

    assert plugin is not None
    assert plugin.name == "dns"
    assert plugin.version == "0.1.0"

def test_http_plugin_is_registered():
    manager = create_plugin_manager()

    plugin = manager.get("http")

    assert plugin is not None
    assert plugin.name == "http"
    assert plugin.version == "0.1.0"
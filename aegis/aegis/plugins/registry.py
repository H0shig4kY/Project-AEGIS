from aegis.plugins.builtin.dns.plugin import DNSPlugin
from aegis.plugins.builtin.http.plugin import HTTPPlugin
from aegis.plugins.builtin.service.plugin import ServiceDiscoveryPlugin
from aegis.plugins.manager import PluginManager
from aegis.plugins.builtin.tls.plugin import (
    TLSPlugin,
)

def create_plugin_manager() -> PluginManager:
    manager = PluginManager()

    manager.register(DNSPlugin())
    manager.register(HTTPPlugin())
    manager.register(ServiceDiscoveryPlugin())
    manager.register(TLSPlugin())

    return manager
from aegis.plugins.base import Plugin

class PluginManager:
    def __init__(self):
        self._plugins: dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        if plugin.name in self._plugins:
            raise ValueError(
                f"Plugin already registered: {plugin.name}"
            )

        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)

    def list(self) -> list[Plugin]:
        return list(self._plugins.values())

    def remove(self, name: str) -> bool:
        if name not in self._plugins:
            return False

        del self._plugins[name]

        return True

    def execute(self, name: str, context):
        plugin = self.get(name)

        if plugin is None:
            raise ValueError(
                f"Plugin not found: {name}"
            )

        return plugin.execute(context)
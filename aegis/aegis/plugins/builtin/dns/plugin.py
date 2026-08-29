import socket

from aegis.assessment import AssessmentContext
from aegis.models import (
    CoverageType,
    ExecutionCoverage,
    TargetType,
)
from aegis.plugins.base import Plugin
from aegis.results import Observation, PluginResult

def resolve_domain(domain: str) -> list[str]:
    addresses = set()

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM,
        )

        for result in results:
            address = result[4][0]
            addresses.add(address)

    except socket.gaierror:
        return []

    return sorted(addresses)

class DNSPlugin(Plugin):
    name = "dns"
    version = "0.1.0"
    description = "Resolve DNS addresses for in-scope domains."

    def execute(
        self,
        context: AssessmentContext,
    ) -> PluginResult:
        observations = []
        coverage = []

        for target in context.scope.list():
            if target.type != TargetType.DOMAIN:
                continue

            coverage.append(
                ExecutionCoverage(
                    plugin=self.name,
                    target=target.value,
                    coverage_type=(
                        CoverageType.DNS
                    ),
                )
            )

            addresses = resolve_domain(
                target.value
            )

            observations.append(
                Observation(
                    target=target.value,
                    type="dns_resolution",
                    data={
                        "addresses": addresses,
                    },
                )
            )

        return PluginResult(
            plugin=self.name,
            version=self.version,
            observations=observations,
            coverage=coverage,
        )
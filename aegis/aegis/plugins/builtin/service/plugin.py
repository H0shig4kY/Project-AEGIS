import socket

from aegis.assessment import AssessmentContext
from aegis.models import (
    FingerprintConfidence,
    FingerprintSource,
    TargetType,
    CoverageType,
    ExecutionCoverage,
)
from aegis.plugins.base import Plugin
from aegis.results import Observation, PluginResult
from aegis.plugins.builtin.service.banner_parser import (
    parse_banner,
)

DEFAULT_PORTS = [
    22,
    80,
    443,
]

def check_tcp_port(
    host: str,
    port: int,
    timeout: float = 1.0,
) -> bool:
    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ):
            return True

    except (
        OSError,
        TimeoutError,
    ):
        return False

def grab_banner(
    host: str,
    port: int,
    timeout: float = 1.0,
    max_bytes: int = 256,
) -> str | None:
    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as sock:
            sock.settimeout(timeout)

            data = sock.recv(max_bytes)

            if not data:
                return None

            return data.decode(
                "utf-8",
                errors="replace",
            ).strip()

    except (
        OSError,
        TimeoutError,
    ):
        return None

def identify_service(port: int) -> dict:
    mapping = {
        22: {
            "service_name": "ssh",
            "tls": False,
        },
        80: {
            "service_name": "http",
            "tls": False,
        },
        443: {
            "service_name": "https",
            "tls": True,
        },
    }

    return mapping.get(
        port,
        {
            "service_name": "unknown",
            "tls": False,
        },
    )

def refine_service(
    port: int,
    banner: str | None,
) -> dict:
    fingerprint = identify_service(port)

    if not banner:
        return fingerprint

    normalized = banner.lower()

    if normalized.startswith("ssh-"):
        return {
            "service_name": "ssh",
            "tls": False,
        }

    if "http/" in normalized:
        return {
            "service_name": "http",
            "tls": False,
        }

    return fingerprint

class ServiceDiscoveryPlugin(Plugin):
    name = "service"
    version = "0.1.0"
    description = (
        "Check a small explicit set of TCP ports "
        "on in-scope domains and IP addresses."
    )

    def __init__(
        self,
        ports: list[int] | None = None,
    ):
        self.ports = ports or list(
            DEFAULT_PORTS
        )

    def execute(
        self,
        context: AssessmentContext,
    ) -> PluginResult:
        observations = []
        coverage = []

        for target in context.scope.list():
            if target.type not in {
                TargetType.DOMAIN,
                TargetType.IP,
            }:
                continue

            # Coverage representa aquilo que esta
            # execução efetivamente tentou verificar.
            coverage.append(
                ExecutionCoverage(
                    plugin=self.name,
                    target=target.value,
                    coverage_type=(
                        CoverageType.SERVICE
                    ),
                    ports=list(self.ports),
                )
            )

            for port in self.ports:
                if not check_tcp_port(
                    target.value,
                    port,
                ):
                    continue

                banner = grab_banner(
                    target.value,
                    port,
                )

                # Fingerprint base por porta,
                # refinado pelo banner quando possível.
                fingerprint = refine_service(
                    port,
                    banner,
                )

                # Extrair produto e versão do banner.
                banner_info = parse_banner(
                    banner
                )

                product = banner_info.get(
                    "product"
                )

                version = banner_info.get(
                    "version"
                )

                # Por defeito, a identificação vem
                # apenas da porta conhecida.
                confidence = (
                    FingerprintConfidence.MEDIUM
                )

                fingerprint_source = (
                    FingerprintSource.PORT
                )

                # Um banner reconhecido fornece
                # evidência mais forte.
                if (
                    banner is not None
                    and (
                        product is not None
                        or banner.lower().startswith(
                            "ssh-"
                        )
                        or "http/" in banner.lower()
                    )
                ):
                    confidence = (
                        FingerprintConfidence.HIGH
                    )

                    fingerprint_source = (
                        FingerprintSource.BANNER
                    )

                observations.append(
                    Observation(
                        target=target.value,
                        type="service_open",
                        data={
                            "host": target.value,
                            "port": port,
                            "transport": "tcp",
                            "service_name": (
                                fingerprint.get(
                                    "service_name",
                                    "unknown",
                                )
                            ),
                            "tls": fingerprint.get(
                                "tls",
                                False,
                            ),
                            "banner": banner,
                            "product": product,
                            "version": version,
                            "confidence": (
                                confidence.value
                            ),
                            "fingerprint_source": (
                                fingerprint_source.value
                            ),
                        },
                    )
                )

        return PluginResult(
            plugin=self.name,
            version=self.version,
            observations=observations,
            coverage=coverage,
        )
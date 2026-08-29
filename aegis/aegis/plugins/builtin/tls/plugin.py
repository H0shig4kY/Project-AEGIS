import hashlib
import socket
import ssl

from aegis.assessment import AssessmentContext
from aegis.models import (
    CoverageType,
    ExecutionCoverage,
    TargetType,
)
from aegis.plugins.base import Plugin
from aegis.results import Observation, PluginResult


class TLSPlugin(Plugin):
    name = "tls"
    version = "0.1.0"
    description = (
        "Inspect TLS services for explicitly "
        "in-scope domains and IP addresses."
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

            observation = inspect_tls(
                target.value,
                443,
            )

            if observation is not None:
                observations.append(
                    observation
                )

            coverage.append(
                ExecutionCoverage(
                    plugin=self.name,
                    target=target.value,
                    coverage_type=CoverageType.TLS,
                )
            )

        return PluginResult(
            plugin=self.name,
            version=self.version,
            observations=observations,
            coverage=coverage,
        )


def inspect_tls(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Observation | None:
    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=host,
            ) as tls_socket:
                cert = tls_socket.getpeercert()
                cert_binary = (
                    tls_socket.getpeercert(
                        binary_form=True
                    )
                )

                cipher = tls_socket.cipher()
                tls_version = tls_socket.version()

    except (
        OSError,
        ssl.SSLError,
        TimeoutError,
    ):
        return None

    certificate_sha256 = None

    if cert_binary:
        certificate_sha256 = hashlib.sha256(
            cert_binary
        ).hexdigest()

    subject = cert.get("subject")
    issuer = cert.get("issuer")
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")

    san_entries = cert.get(
        "subjectAltName",
        [],
    )

    sans = [
        value
        for kind, value in san_entries
        if kind == "DNS"
    ]

    cipher_name = None

    if cipher:
        cipher_name = cipher[0]

    return Observation(
        target=host,
        type="tls_handshake",
        data={
            "host": host,
            "port": port,
            "tls_version": tls_version,
            "cipher": cipher_name,
            "subject": subject,
            "issuer": issuer,
            "valid_from": not_before,
            "valid_to": not_after,
            "sans": sans,
            "certificate_sha256": (
                certificate_sha256
            ),
        },
    )
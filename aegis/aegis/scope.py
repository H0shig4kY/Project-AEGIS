import ipaddress
import re
from urllib.parse import urlparse

from aegis.models import (
    Asset,
    AssetType,
    Target,
    TargetType,
)
from aegis.results import (
    RejectionReason,
    ScopeDecision,
)


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.)+"
    r"[a-zA-Z]{2,63}$"
)


class ScopeEngine:
    def __init__(self) -> None:
        self._targets: list[Target] = []

    def add(self, value: str) -> Target:
        value = value.strip()

        if not value:
            raise ValueError(
                "Target cannot be empty."
            )

        target = self._classify(value)

        if target not in self._targets:
            self._targets.append(target)

        return target

    def list(self) -> list[Target]:
        return list(self._targets)

    def contains(self, value: str) -> bool:
        return any(
            target.value == value
            for target in self._targets
        )

    def is_in_scope(
        self,
        asset: Asset,
    ) -> bool:
        if asset.type == AssetType.DOMAIN:
            return self._domain_in_scope(
                asset.value
            )

        if asset.type == AssetType.IP:
            return self._ip_in_scope(
                asset.value
            )

        return False

    def _domain_in_scope(
        self,
        value: str,
    ) -> bool:
        domain = value.lower().rstrip(".")

        for target in self._targets:
            if target.type == TargetType.DOMAIN:
                target_domain = (
                    target.value
                    .lower()
                    .rstrip(".")
                )

                if domain == target_domain:
                    return True

            elif (
                target.type
                == TargetType.WILDCARD
            ):
                wildcard_domain = (
                    target.value[2:]
                    .lower()
                    .rstrip(".")
                )

                if (
                    domain != wildcard_domain
                    and domain.endswith(
                        "." + wildcard_domain
                    )
                ):
                    return True

        return False

    def _ip_in_scope(
        self,
        value: str,
    ) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False

        for target in self._targets:
            if target.type == TargetType.IP:
                try:
                    target_ip = ipaddress.ip_address(
                        target.value
                    )
                except ValueError:
                    continue

                if ip == target_ip:
                    return True

            elif target.type == TargetType.CIDR:
                try:
                    network = ipaddress.ip_network(
                        target.value,
                        strict=False,
                    )
                except ValueError:
                    continue

                if ip in network:
                    return True

        return False

    @staticmethod
    def _classify(
        value: str,
    ) -> Target:
        # IP address
        try:
            ipaddress.ip_address(value)

            return Target(
                value=value,
                type=TargetType.IP,
            )
        except ValueError:
            pass

        # CIDR
        try:
            ipaddress.ip_network(
                value,
                strict=False,
            )

            return Target(
                value=value,
                type=TargetType.CIDR,
            )
        except ValueError:
            pass

        # Wildcard domain
        if value.startswith("*."):
            domain = value[2:]

            if DOMAIN_PATTERN.match(domain):
                return Target(
                    value=value,
                    type=TargetType.WILDCARD,
                )

            raise ValueError(
                f"Invalid wildcard domain: "
                f"{value}"
            )

        # Normal domain
        if DOMAIN_PATTERN.match(value):
            return Target(
                value=value,
                type=TargetType.DOMAIN,
            )

        raise ValueError(
            f"Invalid target: {value}"
        )

    def evaluate(
        self,
        asset: Asset,
    ) -> ScopeDecision:
        if asset.type == AssetType.DOMAIN:
            allowed = self._domain_in_scope(
                asset.value
            )

            if allowed:
                return ScopeDecision(
                    allowed=True,
                )

            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.OUTSIDE_SCOPE
                ),
            )

        if asset.type == AssetType.IP:
            allowed = self._ip_in_scope(
                asset.value
            )

            if allowed:
                return ScopeDecision(
                    allowed=True,
                )

            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.OUTSIDE_SCOPE
                ),
            )

        if asset.type == AssetType.URL:
            return self._evaluate_url(
                asset.value
            )

        if asset.type == AssetType.SERVICE:
            return self._evaluate_service(
                asset.value
            )

        if (
            asset.type
            == AssetType.CERTIFICATE
        ):
            return self._evaluate_certificate(
                asset
            )

        return ScopeDecision(
            allowed=False,
            reason=(
                RejectionReason.UNSUPPORTED_TYPE
            ),
        )

    def _evaluate_url(
        self,
        value: str,
    ) -> ScopeDecision:
        parsed = urlparse(value)

        if parsed.scheme not in {
            "http",
            "https",
        }:
            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.UNSUPPORTED_TYPE
                ),
            )

        hostname = parsed.hostname

        if not hostname:
            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.UNSUPPORTED_TYPE
                ),
            )

        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            allowed = self._ip_in_scope(
                hostname
            )
        else:
            allowed = self._domain_in_scope(
                hostname
            )

        if allowed:
            return ScopeDecision(
                allowed=True,
            )

        return ScopeDecision(
            allowed=False,
            reason=(
                RejectionReason.OUTSIDE_SCOPE
            ),
        )

    def _evaluate_service(
        self,
        value: str,
    ) -> ScopeDecision:
        host = None
        port_text = None

        # IPv6:
        # [2001:db8::1]:443
        if value.startswith("["):
            closing = value.find("]")

            if closing == -1:
                return ScopeDecision(
                    allowed=False,
                    reason=(
                        RejectionReason.UNSUPPORTED_TYPE
                    ),
                )

            host = value[1:closing]

            remainder = value[
                closing + 1:
            ]

            if not remainder.startswith(":"):
                return ScopeDecision(
                    allowed=False,
                    reason=(
                        RejectionReason.UNSUPPORTED_TYPE
                    ),
                )

            port_text = remainder[1:]

        else:
            if ":" not in value:
                return ScopeDecision(
                    allowed=False,
                    reason=(
                        RejectionReason.UNSUPPORTED_TYPE
                    ),
                )

            host, port_text = (
                value.rsplit(":", 1)
            )

        if not host or not port_text:
            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.UNSUPPORTED_TYPE
                ),
            )

        try:
            port = int(port_text)
        except ValueError:
            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.UNSUPPORTED_TYPE
                ),
            )

        if port < 1 or port > 65535:
            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.UNSUPPORTED_TYPE
                ),
            )

        try:
            ipaddress.ip_address(host)

            allowed = self._ip_in_scope(
                host
            )

        except ValueError:
            allowed = (
                self._domain_in_scope(
                    host
                )
            )

        if allowed:
            return ScopeDecision(
                allowed=True,
            )

        return ScopeDecision(
            allowed=False,
            reason=(
                RejectionReason.OUTSIDE_SCOPE
            ),
        )

    def _evaluate_certificate(
        self,
        asset: Asset,
    ) -> ScopeDecision:
        """
        A certificate is a derived asset.

        Its authorization comes from the host
        that presented it, never from its SANs.
        """

        host = asset.metadata.get(
            "host"
        )

        if not isinstance(host, str):
            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.UNSUPPORTED_TYPE
                ),
            )

        host = host.strip()

        if not host:
            return ScopeDecision(
                allowed=False,
                reason=(
                    RejectionReason.UNSUPPORTED_TYPE
                ),
            )

        try:
            ipaddress.ip_address(host)

            allowed = self._ip_in_scope(
                host
            )

        except ValueError:
            allowed = (
                self._domain_in_scope(
                    host
                )
            )

        if allowed:
            return ScopeDecision(
                allowed=True,
            )

        return ScopeDecision(
            allowed=False,
            reason=(
                RejectionReason.OUTSIDE_SCOPE
            ),
        )
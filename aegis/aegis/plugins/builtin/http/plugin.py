from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from aegis.assessment import AssessmentContext
from aegis.models import TargetType
from aegis.plugins.base import Plugin
from aegis.results import Observation, PluginResult

def probe_http(
    domain: str,
    timeout: float = 5.0,
) -> dict | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"

        request = Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": "AEGIS/ARGUS/0.1",
            },
        )

        try:
            with urlopen(
                request,
                timeout=timeout,
            ) as response:
                return {
                    "url": url,
                    "scheme": scheme,
                    "status_code": response.status,
                    "server": response.headers.get(
                        "Server"
                    ),
                    "content_type": response.headers.get(
                        "Content-Type"
                    ),
                }

        except HTTPError as exc:
            # An HTTP error response still proves that
            # an HTTP service answered.
            return {
                "url": url,
                "scheme": scheme,
                "status_code": exc.code,
                "server": exc.headers.get(
                    "Server"
                ),
                "content_type": exc.headers.get(
                    "Content-Type"
                ),
            }

        except (URLError, TimeoutError):
            continue

    return None

class HTTPPlugin(Plugin):
    name = "http"
    version = "0.1.0"
    description = (
        "Probe HTTP/HTTPS services for explicitly "
        "in-scope domains."
    )

    def execute(
        self,
        context: AssessmentContext,
    ) -> PluginResult:
        observations = []

        for target in context.scope.list():
            if target.type != TargetType.DOMAIN:
                continue

            probe = probe_http(target.value)

            if probe is None:
                continue

            observations.append(
                Observation(
                    target=target.value,
                    type="http_probe",
                    data=probe,
                )
            )

        return PluginResult(
            plugin=self.name,
            version=self.version,
            observations=observations,
        )
import hashlib
import json

from aegis.results import (
    Observation,
    PluginResult,
)


def _sha256_payload(payload: dict) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(
        encoded
    ).hexdigest()


def build_observation_id(
    plugin: str,
    observation: Observation,
) -> str:
    payload = {
        "plugin": plugin,
        "type": observation.type,
        "target": observation.target,
        "data": observation.data,
    }

    return _sha256_payload(payload)


def build_result_id(
    result: PluginResult,
) -> str:
    payload = {
        "plugin": result.plugin,
        "version": result.version,
        "status": result.status,
        "timestamp": result.timestamp.isoformat(),
        "observations": [
            observation.model_dump(
                mode="json"
            )
            for observation in result.observations
        ],
    }

    return _sha256_payload(payload)
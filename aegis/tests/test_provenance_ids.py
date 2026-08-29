from aegis.provenance import (
    build_observation_id,
    build_result_id,
)
from aegis.results import (
    Observation,
    PluginResult,
)


def test_same_observation_produces_same_id():
    first = Observation(
        target="example.com",
        type="service_open",
        data={
            "host": "example.com",
            "port": 443,
        },
    )

    second = Observation(
        target="example.com",
        type="service_open",
        data={
            "port": 443,
            "host": "example.com",
        },
    )

    first_id = build_observation_id(
        "service",
        first,
    )

    second_id = build_observation_id(
        "service",
        second,
    )

    assert first_id == second_id


def test_different_observation_produces_different_id():
    first = Observation(
        target="example.com",
        type="service_open",
        data={
            "port": 80,
        },
    )

    second = Observation(
        target="example.com",
        type="service_open",
        data={
            "port": 443,
        },
    )

    assert (
        build_observation_id("service", first)
        != build_observation_id("service", second)
    )


def test_plugin_is_part_of_observation_id():
    observation = Observation(
        target="example.com",
        type="service_open",
        data={
            "port": 443,
        },
    )

    assert (
        build_observation_id(
            "service",
            observation,
        )
        != build_observation_id(
            "other",
            observation,
        )
    )


def test_same_result_produces_same_id():
    result = PluginResult(
        plugin="service",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "port": 443,
                },
            )
        ],
    )

    first_id = build_result_id(result)
    second_id = build_result_id(result)

    assert first_id == second_id


def test_result_changes_when_observation_changes():
    first = PluginResult(
        plugin="service",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "port": 80,
                },
            )
        ],
    )

    second = PluginResult(
        plugin="service",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "port": 443,
                },
            )
        ],
    )

    assert (
        build_result_id(first)
        != build_result_id(second)
    )
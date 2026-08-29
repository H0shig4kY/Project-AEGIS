from pathlib import Path

from aegis.results import Observation, PluginResult
from aegis.result_store import ResultStore

def create_result() -> PluginResult:
    return PluginResult(
        plugin="dns",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="dns_resolution",
                data={
                    "addresses": [
                        "192.0.2.10",
                    ]
                },
            )
        ],
    )

def test_save_result(tmp_path: Path):
    store = ResultStore(
        tmp_path / "results"
    )

    result = create_result()

    path = store.save(result)

    assert path.exists()
    assert path.suffix == ".json"
    assert path.parent == tmp_path / "results"

def test_list_results(tmp_path: Path):
    store = ResultStore(
        tmp_path / "results"
    )

    store.save(create_result())
    store.save(create_result())

    results = store.list()

    assert len(results) == 2

def test_load_result(tmp_path: Path):
    store = ResultStore(
        tmp_path / "results"
    )

    original = create_result()

    path = store.save(original)

    loaded = store.load(path)

    assert loaded.plugin == "dns"
    assert loaded.version == "0.1.0"
    assert len(loaded.observations) == 1

    observation = loaded.observations[0]

    assert observation.target == "example.com"
    assert observation.type == "dns_resolution"
import pytest

def pytest_collection_modifyitems(config, items):
    markexpr = config.getoption("markexpr")
    if "network" not in markexpr:
        skip_network = pytest.mark.skip(reason="need -m network option to run")
        for item in items:
            if "network" in item.keywords:
                item.add_marker(skip_network)

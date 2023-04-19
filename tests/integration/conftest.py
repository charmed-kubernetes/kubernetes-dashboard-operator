import pytest


def pytest_addoption(parser):
    parser.addoption("--arch", action="store", default="amd64")
    parser.addoption("--series", action="store", default="focal")


@pytest.fixture
def arch(request):
    return request.config.getoption("--arch")


@pytest.fixture
def series(request):
    return request.config.getoption("--series")

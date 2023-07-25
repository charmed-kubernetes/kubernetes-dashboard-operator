#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import shlex
import ssl
import urllib.request
from pathlib import Path

import pytest
import yaml
from lightkube import Client
from lightkube.resources.core_v1 import ConfigMap, Secret, Service, ServiceAccount
from lightkube.resources.rbac_authorization_v1 import (
    ClusterRole,
    ClusterRoleBinding,
    Role,
    RoleBinding,
)
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)


METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, arch: str, series: str):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    # build and deploy charm from local source folder
    charm = next(Path(".").glob("kubernetes-dashboard*.charm"), None)
    if not charm:
        logger.info("Build Charm...")
        charm = await ops_test.build_charm(".")

    bundles = [Path("tests/data/charm.yaml")]
    context = {
        "arch": arch,
        "charm": charm.resolve(),
        "model_name": ops_test.model_name,
        "resources": {
            "dashboard-image": METADATA["resources"]["dashboard-image"]["upstream-source"],
            "scraper-image": METADATA["resources"]["scraper-image"]["upstream-source"],
        },
        "series": series,
    }
    (bundle,) = await ops_test.async_render_bundles(*bundles, **context)

    logger.info("Deploy Charm...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle} --trust"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"
    logger.info(stdout)

    # issuing dummy update_status just to trigger an event
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(apps=["dashboard"], status="active", timeout=60 * 5)
        assert ops_test.model.applications["dashboard"].units[0].workload_status == "active"


@pytest.mark.abort_on_fail
async def test_kubernetes_resources_created(ops_test: OpsTest):
    client = Client()
    # A slightly naive test that ensures the relevant Kubernetes resources were created.
    # If any of these fail, an exception is raised and the test will fail
    client.get(ClusterRole, name="kubernetes-dashboard")
    client.get(ClusterRoleBinding, name="kubernetes-dashboard")
    client.get(ConfigMap, name="kubernetes-dashboard-settings", namespace=ops_test.model_name)
    client.get(Role, name="kubernetes-dashboard", namespace=ops_test.model_name)
    client.get(RoleBinding, name="kubernetes-dashboard", namespace=ops_test.model_name)
    client.get(Secret, name="kubernetes-dashboard-csrf", namespace=ops_test.model_name)
    client.get(Secret, name="kubernetes-dashboard-key-holder", namespace=ops_test.model_name)
    client.get(ServiceAccount, name="kubernetes-dashboard", namespace=ops_test.model_name)
    client.get(Service, name="dashboard-metrics-scraper", namespace=ops_test.model_name)
    client.get(Service, name="dashboard", namespace=ops_test.model_name)


@pytest.mark.abort_on_fail
async def test_dashboard_is_up(ops_test: OpsTest):
    client = Client()
    service = client.get(Service, name="dashboard", namespace=ops_test.model_name)
    address = service.spec.clusterIP

    url = f"https://{address}:443"
    logger.info("dashboard public address: https://%s", url)

    response = urllib.request.urlopen(
        url, data=None, timeout=2.0, context=ssl._create_unverified_context()
    )
    assert response.code == 200

#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.


import ipaddress
import json
import logging
import shlex
import ssl
import urllib.request
from pathlib import Path

import pytest
import yaml
from cryptography.x509 import DNSName, ObjectIdentifier, load_pem_x509_certificate
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
    assert "Kubernetes Dashboard" in response.read().decode("utf-8")
    assert response.code == 200


async def test_ingress_integration(ops_test: OpsTest):
    await ops_test.model.deploy("traefik-k8s", channel="edge", trust=True)
    await ops_test.model.integrate("traefik-k8s:certificates", "tls-certificates:certificates")
    await ops_test.model.integrate("dashboard:ingress", "traefik-k8s:ingress")
    await ops_test.model.wait_for_idle(
        apps=["dashboard", "traefik-k8s"], status="active", timeout=60 * 5
    )

    # Ensure the dashboard is accessible via the traefik ingress
    traefik_k8s = ops_test.model.applications["traefik-k8s"].units[0]
    result = await traefik_k8s.run_action("show-proxied-endpoints")
    await result.wait()
    endpoints = json.loads(result.results["proxied-endpoints"])
    url = endpoints["dashboard"]["url"]

    response = urllib.request.urlopen(
        url, data=None, timeout=2.0, context=ssl._create_unverified_context()
    )
    assert "Kubernetes Dashboard" in response.read().decode("utf-8")
    assert response.code == 200


def contains_known_fqdns(fqdn: str, namespace: str):
    endpoints_fqdn = f"dashboard-endpoints.{namespace}"
    cluster_fqdn = f"dashboard.{namespace}"
    return endpoints_fqdn in fqdn or cluster_fqdn in fqdn


def get_dashboard_certificate(namespace: str, address=None):
    """Retrieve Certificate of the dashboard service in the namespace."""
    if address is None:
        client = Client()
        service = client.get(Service, name="dashboard", namespace=namespace)
        address = service.spec.clusterIP, 443

    cert_str = ssl.get_server_certificate(address)
    cert = load_pem_x509_certificate(cert_str.encode())

    expected_common_name = f"dashboard.{namespace}"
    common_name = cert.subject.get_attributes_for_oid(ObjectIdentifier("2.5.4.3"))
    val, *_ = (_.value for _ in common_name)

    assert val == expected_common_name, f"Unexpected certificate for service at {address}"

    sans = cert.extensions.get_extension_for_oid(ObjectIdentifier("2.5.29.17"))
    assert len(sans.value) == 6, "Expect 6 addresses in SANS"
    for attr in sans.value:
        if isinstance(attr, DNSName):
            try:
                # It's possible that DNSNames actually are
                # misrepresented IP Addresses -- filter those out
                ipaddress.ip_address(attr.value)
            except ValueError:
                # Non-IP Addresses should be fqdn names
                assert contains_known_fqdns(attr.value, namespace)

    return cert


async def test_certificate_is_remotelysigned(ops_test: OpsTest):
    cert = get_dashboard_certificate(ops_test.model.name)
    assert cert.issuer != cert.subject, "Certificate is Self-signed"


async def test_certificate_is_selfsigned(ops_test: OpsTest):
    dashboard = ops_test.model.applications["dashboard"]
    await dashboard.remove_relation("certificates", "tls-certificates:certificates")
    await ops_test.model.wait_for_idle(apps=["dashboard"], status="active", timeout=60 * 5)

    cert = get_dashboard_certificate(ops_test.model.name)
    assert cert.issuer == cert.subject, "Certificate isn't Self-signed"

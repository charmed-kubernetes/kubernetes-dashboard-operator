import unittest
from functools import lru_cache
from ipaddress import IPv4Address

from ops.interface_tls_certificates import CertificatesRequires
from ops.interface_tls_certificates.model import Certificate
from relation_cert import CertificatesRelation


class TestRelationCert(unittest.TestCase):
    def setUp(self) -> None:
        self.charm = unittest.mock.MagicMock()
        self.fqdn = ["testCN", "abc"]
        self.ips = [IPv4Address("1.2.3.4")]
        mock_telco = (
            "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2"
        )
        mock_legacy = "relation_cert.CertificatesRequires"
        with unittest.mock.patch(mock_telco) as telco:
            with unittest.mock.patch(mock_legacy, autospec=CertificatesRequires) as legacy:
                self.telco_relation = telco.return_value
                self.legacy_relation = legacy.return_value
                self.legacy_relation.ca = "ca-cert-data"
                self.legacy_relation.server_certs_map = {}
                self.interface_tls = CertificatesRelation(self.charm)

        @lru_cache
        def relation_mapper(relation_name):
            relation = unittest.mock.MagicMock()
            relation.data = {
                self.charm.app: {},
                self.interface_tls.model.unit: {},
            }

            return relation

        self.interface_tls.model.get_relation.side_effect = relation_mapper

    def test_install(self):
        replicas = self.interface_tls.model.get_relation("replicas")
        replicas_data = replicas.data[self.charm.app]
        install_event = unittest.mock.MagicMock()
        self.interface_tls.install(install_event)
        assert isinstance(replicas_data["private_key"], str)

    def test_legacy_available(self):
        subject = self.fqdn[0]
        cert = Certificate(
            cert_type="server",
            common_name=subject,
            cert="public-data",
            key="private-data",
        )
        self.legacy_relation.server_certs_map = {subject: cert}
        self.legacy_relation.is_ready = True
        cert = self.interface_tls.certificate()
        assert cert
        assert cert.cert == b"public-data"
        assert cert.key == b"private-data"
        assert cert.ca == b"ca-cert-data"

    def test_legacy_not_available(self):
        self.legacy_relation.is_ready = True
        self.legacy_relation.server_certs_map = {}
        assert self.interface_tls.certificate() is None

    def test_telco_relation(self):
        self.legacy_relation.is_ready = False
        assert not self.interface_tls.certificate()

        install_event = unittest.mock.MagicMock()
        self.interface_tls.install(install_event)
        assert not self.interface_tls.certificate()

        replicas = self.interface_tls.model.get_relation("replicas")
        replicas_data = replicas.data[self.charm.app]
        replicas_data["csr"] = unittest.mock.MagicMock()
        self.interface_tls._csr_attrs = unittest.mock.MagicMock(
            return_value=(self.fqdn[0], self.fqdn, self.ips)
        )

        assert not self.interface_tls.certificate()
        available_event = unittest.mock.MagicMock()
        available_event.certificate = "123"
        available_event.chain = ["abc", "def"]

        self.interface_tls._on_available(available_event)
        cert = self.interface_tls.certificate()
        assert cert.common_name == self.fqdn[0]
        assert cert.cert == b"123\nabc\n\ndef"
        assert cert.key == replicas_data["private_key"].encode()
        assert cert.ca == available_event.ca.encode.return_value

    def test_request(self):
        subject = self.fqdn[0]
        install_event = unittest.mock.MagicMock()
        self.interface_tls.install(install_event)

        self.interface_tls.request(self.fqdn, self.ips)
        expected_sans = self.fqdn + [str(_) for _ in self.ips]
        self.legacy_relation.request_server_cert.assert_called_once_with(subject, expected_sans)

        replicas = self.interface_tls.model.get_relation("replicas")
        certificates = self.interface_tls.model.get_relation("certificates")

        replicas_data = replicas.data[self.charm.app]
        certificate_data = certificates.data[self.interface_tls.model.unit]
        assert isinstance(replicas_data["csr"], str)
        assert isinstance(certificate_data["certificate_signing_requests"], str)

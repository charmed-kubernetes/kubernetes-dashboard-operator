import unittest

from ops.interface_tls_certificates import CertificatesRequires
from ops.interface_tls_certificates.model import Certificate
from relation_cert import CertificatesRelation


class TestRelationCert(unittest.TestCase):
    def setUp(self) -> None:
        self.common_name = "testCN"
        self.charm = unittest.mock.MagicMock()
        with unittest.mock.patch(
            "relation_cert.CertificatesRequires", autospec=CertificatesRequires
        ) as r:
            self.legacy_relation = r.return_value
            self.legacy_relation.ca = "ca-cert-data"
            self.legacy_relation.server_certs_map = {}
            self.interface_tls = CertificatesRelation(self.charm)

    def test_is_available(self):
        cert = Certificate(
            cert_type="server",
            common_name=self.common_name,
            cert="public-data",
            key="private-data",
        )
        self.legacy_relation.server_certs_map = {self.common_name: cert}
        cert = self.interface_tls.certificate(self.common_name)
        assert cert
        assert cert.cert == b"public-data"
        assert cert.key == b"private-data"
        assert cert.ca == b"ca-cert-data"

    def test_is_not_available(self):
        self.legacy_relation.server_certs_map = {}
        assert not self.interface_tls.certificate(self.common_name)

    def test_request(self):
        self.interface_tls.request(self.common_name, ["abc"])
        self.legacy_relation.request_server_cert.assert_called_once_with(self.common_name, ["abc"])

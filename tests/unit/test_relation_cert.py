import unittest
import unittest.mock as mock

from ops.interface_tls_certificates import CertificatesRequires
from ops.interface_tls_certificates.model import Certificate
from relation_cert import RelationCert

class TestRelationCert(unittest.TestCase):
    def setUp(self) -> None:
        self._name = "testCN"
        self.relation = mock.MagicMock(autospec=CertificatesRequires)
        self.relation.ca = "ca-cert-data"

    def with_cert(self, rel_cert: RelationCert):
        cert = Certificate(
            cert_type="server",
            common_name=self._name,
            cert="public-data",
            key="private-data"
        )
        rel_cert._relation.server_certs_map = {self._name: cert}

    def test_request(self):
        rel_cert = RelationCert(self.relation, self._name)
        rel_cert.request(["abc"])
        self.relation.request_server_cert.assert_called_once_with(self._name, ["abc"])
    
    def test_is_available(self):
        rel_cert = RelationCert(self.relation, self._name)
        self.with_cert(rel_cert)
        assert rel_cert.available
    
    def test_is_not_available(self):
        rel_cert = RelationCert(self.relation, self._name)
        self.relation.server_certs_map = {}
        assert not rel_cert.available

    def test_cert_value(self):
        rel_cert = RelationCert(self.relation, self._name)
        self.with_cert(rel_cert)
        assert rel_cert.cert == b"public-data"

    def test_key_value(self):
        rel_cert = RelationCert(self.relation, self._name)
        self.with_cert(rel_cert)
        assert rel_cert.key == b"private-data"

    def test_ca(self):
        rel_cert = RelationCert(self.relation, self._name)
        assert rel_cert.ca == b"ca-cert-data"

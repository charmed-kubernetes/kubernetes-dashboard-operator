import unittest
import unittest.mock as mock
from ipaddress import IPv4Address

from ops.interface_tls_certificates.model import Certificate as OpsCert
from relation_cert import CertificatesRelation, LegacyRequires, TelcoRequires


class TestRelationCert(unittest.TestCase):
    def setUp(self) -> None:
        self.charm = unittest.mock.MagicMock()
        mock_telco = "relation_cert.TelcoRequires"
        mock_legacy = "relation_cert.LegacyRequires"

        with mock.patch(mock_telco, autospec=TelcoRequires):
            with mock.patch(mock_legacy, autospec=LegacyRequires):
                self.interface_tls = CertificatesRelation(self.charm)

    def test_relation(self):
        rel1 = self.interface_tls.relation
        rel2 = self.interface_tls.relation
        assert rel1 is rel2
        self.interface_tls.model.get_relation.assert_called_once_with("certificates")

    def test_install(self):
        event = mock.MagicMock()
        self.interface_tls.install(event)
        self.interface_tls._telco_relation.install.assert_called_once_with(event)

    def test_certificate_by_legacy(self):
        cert = self.interface_tls.certificate()
        self.interface_tls._legacy_relation.get_certificate.assert_called_once_with()
        assert cert == self.interface_tls._legacy_relation.get_certificate.return_value
        self.interface_tls._telco_relation.get_certificate.assert_not_called()

    def test_certificate_by_telco(self):
        self.interface_tls._legacy_relation.get_certificate.return_value = None
        cert = self.interface_tls.certificate()
        self.interface_tls._legacy_relation.get_certificate.assert_called_once_with()
        self.interface_tls._telco_relation.get_certificate.assert_called_once_with()
        assert cert == self.interface_tls._telco_relation.get_certificate.return_value

    def test_request(self):
        names, ips = unittest.mock.MagicMock(), unittest.mock.MagicMock()
        self.interface_tls.request(names, ips)
        self.interface_tls._legacy_relation.request.assert_called_once_with(names, ips)
        self.interface_tls._telco_relation.request.assert_called_once_with(names, ips)


class TestLegacyRequires(unittest.TestCase):
    def setUp(self) -> None:
        self.charm = unittest.mock.MagicMock()
        self.legacy = LegacyRequires(self.charm, "certificates")

    @mock.patch("relation_cert.CertificatesRequires.is_ready", new_callable=mock.PropertyMock)
    def test_certificate_not_ready(self, mock_is_ready):
        mock_is_ready.return_value = False
        cert = self.legacy.get_certificate()
        mock_is_ready.assert_called_once_with()
        assert cert is None

    @mock.patch("relation_cert.CertificatesRequires.is_ready", new_callable=mock.PropertyMock)
    @mock.patch(
        "relation_cert.CertificatesRequires.server_certs_map", new_callable=mock.PropertyMock
    )
    def test_certificate_ready_no_certs_yet(self, mock_certs_map, mock_is_ready):
        mock_certs_map.return_value = {}
        cert = self.legacy.get_certificate()
        mock_is_ready.assert_called_once()
        mock_certs_map.assert_called_once()
        assert cert is None

    @mock.patch("relation_cert.CertificatesRequires.is_ready", new_callable=mock.PropertyMock)
    @mock.patch(
        "relation_cert.CertificatesRequires.server_certs_map", new_callable=mock.PropertyMock
    )
    @mock.patch("relation_cert.CertificatesRequires.ca", new_callable=mock.PropertyMock)
    def test_certificate_ready(self, mock_ca, mock_certs_map, mock_is_ready):
        subject = "testCN"
        cert = OpsCert(
            cert_type="server",
            common_name=subject,
            cert="public-data",
            key="private-data",
        )
        mock_certs_map.return_value = {subject: cert}
        cert = self.legacy.get_certificate()
        mock_is_ready.assert_called_once()
        mock_certs_map.assert_called_once()
        mock_ca.assert_called_once()
        assert cert.common_name == subject
        assert cert.cert == b"public-data"
        assert cert.key == b"private-data"
        assert cert.ca == mock_ca().encode.return_value

    @mock.patch("relation_cert.CertificatesRequires.request_server_cert")
    def test_request(self, mock_request):
        names, ips = ["testCN", "abc"], [IPv4Address("1.2.3.4")]
        self.legacy.request(names, ips)
        mock_request.assert_called_once_with(names[0], names + ["1.2.3.4"])


class TestTelcoRequires(unittest.TestCase):
    def setUp(self) -> None:
        self.charm = unittest.mock.MagicMock()
        self.telco = TelcoRequires(self.charm, "certificates")

    def test_get_replica_data(self):
        event = mock.MagicMock()

        relation = self.telco.model.get_relation()
        relation_app_content = {"valid": "relation-content"}
        relation.data = {self.charm.app: relation_app_content}
        assert self.telco._get_replica_data(event, writable=True) == relation_app_content
        event.defer.assert_not_called()

        self.telco.model.unit.is_leader.return_value = False
        assert self.telco._get_replica_data(event, writable=True) is None
        event.defer.assert_not_called()

        self.telco.model.get_relation.return_value = None
        assert self.telco._get_replica_data(event, writable=True) is None
        event.defer.assert_called_once()

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    @mock.patch("relation_cert.generate_private_key")
    def test_install_no_replica_yet(self, mock_generate_private_key, mock_replica_data):
        mock_replica_data.return_value = None
        event = mock.MagicMock()
        self.telco.install(event)
        mock_replica_data.assert_called_once_with(event, writable=True)
        mock_generate_private_key.assert_not_called()

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    @mock.patch("relation_cert.generate_private_key")
    def test_install_with_replicas(self, mock_generate_private_key, mock_replica_data):
        mock_replica_data.return_value = {"private_key": "something"}
        event = mock.MagicMock()
        self.telco.install(event)
        mock_replica_data.assert_called_once_with(event, writable=True)
        mock_generate_private_key.assert_not_called()

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    @mock.patch("relation_cert.generate_private_key")
    def test_install_empty_replicas(self, mock_generate_private_key, mock_replica_data):
        data = mock_replica_data.return_value = {}
        event = mock.MagicMock()
        self.telco.install(event)
        mock_replica_data.assert_called_once_with(event, writable=True)
        mock_generate_private_key.assert_called_once_with(password=None)
        assert data["private_key"] == mock_generate_private_key.return_value.decode()

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    def test_certificate_not_ready(self, mock_replica_data):
        mock_replica_data.return_value = {}
        cert = self.telco.get_certificate()
        mock_replica_data.assert_called_once_with(None)
        assert cert is None

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    def test_certificate_not_ready_no_csr(self, mock_replica_data):
        mock_replica_data.return_value = {"private_key": "something"}
        cert = self.telco.get_certificate()
        mock_replica_data.assert_called_once_with(None)
        assert cert is None

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    @mock.patch("relation_cert.TelcoRequires._csr_attrs")
    def test_certificate_not_ready_no_ca(self, mock_csr_attrs, mock_replica_data):
        mock_replica_data.return_value = {
            "private_key": "private-data",
            "csr": "--certificate-signing-request--",
        }
        names, ips = ["testCN", "abc"], [IPv4Address("1.2.3.4")]
        mock_csr_attrs.return_value = (names[0], names, ips)

        cert = self.telco.get_certificate()

        mock_replica_data.assert_called_once_with(None)
        mock_csr_attrs.assert_called_once_with(b"--certificate-signing-request--")
        assert cert is None

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    @mock.patch("relation_cert.TelcoRequires._csr_attrs")
    def test_certificate_ready(self, mock_csr_attrs, mock_replica_data):
        mock_replica_data.return_value = {
            "private_key": "private-data",
            "csr": "--certificate-signing-request--",
            "certificate": "public-data",
            "ca": "ca-data",
            "chain": "chain1\n\nchain2",
        }
        names, ips = ["testCN", "abc"], [IPv4Address("1.2.3.4")]
        mock_csr_attrs.return_value = (names[0], names, ips)

        cert = self.telco.get_certificate()

        mock_replica_data.assert_called_once_with(None)
        mock_csr_attrs.assert_called_once_with(b"--certificate-signing-request--")
        assert cert.common_name == "testCN"
        assert cert.cert == b"public-data"
        assert cert.key == b"private-data"
        assert cert.ca == b"ca-data"

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    @mock.patch("relation_cert.TLSCertificatesRequiresV2.request_certificate_creation")
    @mock.patch("relation_cert.generate_csr")
    def test_request(self, mock_generate_csr, mock_request, mock_replica_data):
        names, ips = ["testCN", "abc"], [IPv4Address("1.2.3.4")]

        mock_replica_data.return_value = None
        self.telco.request(names, ips)
        mock_generate_csr.assert_not_called()

        data = mock_replica_data.return_value = {
            "private_key": "private-data",
        }
        self.telco.request(names, ips)
        mock_generate_csr.assert_called_once_with(
            private_key=b"private-data",
            private_key_password=None,
            subject="testCN",
            sans_dns=names,
            sans_ip=ips,
        )
        mock_request.assert_called_once_with(
            certificate_signing_request=mock_generate_csr.return_value
        )
        assert data["csr"] == mock_generate_csr.return_value.decode()

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    def test_csr_response(self, mock_replica_data):
        data = mock_replica_data.return_value = {"csr": "--my-csr--"}
        event = mock.MagicMock()
        event.chain = ["chain1", "chain2"]
        self.telco._on_available(event)
        assert data == {
            "certificate": event.certificate,
            "ca": event.ca,
            "chain": "chain1\n\nchain2",
            "csr": "--my-csr--",
        }

    @mock.patch("relation_cert.TelcoRequires._get_replica_data")
    @mock.patch("relation_cert.TLSCertificatesRequiresV2.request_certificate_renewal")
    @mock.patch("relation_cert.generate_csr")
    @mock.patch("relation_cert.TelcoRequires._csr_attrs")
    def test_invalidate(self, mock_csr_attrs, mock_generate_csr, mock_request, mock_replica_data):
        data = mock_replica_data.return_value = {
            "private_key": "private-data",
            "certificate": "--cert-data--",
            "ca": "--ca-data--",
            "chain": "chain1\n\nchain2",
            "csr": "--my-csr--",
        }
        names, ips = ["testCN", "abc"], [IPv4Address("1.2.3.4")]
        mock_csr_attrs.return_value = (names[0], names, ips)
        new_csr = mock_generate_csr.return_value = b"--new-csr--"
        event = mock.MagicMock()
        event.reason = "revoked"
        self.telco._on_invalidate(event)
        mock_request.assert_called_once_with(
            old_certificate_signing_request=b"--my-csr--",
            new_certificate_signing_request=new_csr,
        )
        assert data == {"private_key": "private-data", "csr": "--new-csr--"}

"""Various ways for the admission webhook service to request a TLS cert package."""

from typing import List

from ops.interface_tls_certificates.requires import CertificatesRequires


class RelationCert:
    """Request certificate package via the tls-interface relation."""

    def __init__(self, relation: CertificatesRequires, common_name: str):
        self._relation = relation
        self._common_name = common_name

    def request(self, sans: List[str]):
        """Generate certs based on the common_name and sans."""
        self._relation.request_server_cert(self._common_name, sans)

    @property
    def available(self):
        """Cert is available when it appears in the certs map."""
        return self._common_name in self._relation.server_certs_map

    @property
    def cert(self) -> bytes:
        """Representation of a tls certificate."""
        certificate = self._relation.server_certs_map[self._common_name]
        return certificate.cert.encode()

    @property
    def key(self) -> bytes:
        """Representation of a private key file."""
        certificate = self._relation.server_certs_map[self._common_name]
        return certificate.key.encode()

    @property
    def ca(self) -> bytes:
        """Representation of a ca cert."""
        return self._relation.ca.encode()

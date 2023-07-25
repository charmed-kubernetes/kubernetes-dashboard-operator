"""Various ways for the admission webhook service to request a TLS cert package."""

from dataclasses import dataclass
from typing import List, Optional

from ops.interface_tls_certificates import CertificatesRequires


@dataclass
class Certificate:
    """Representation of a certificate."""

    common_name: str
    cert: bytes
    key: bytes
    ca: bytes


class CertificatesRelation:
    """Request certificate package via the tls-interface relation."""

    def __init__(self, charm, endpoint: str = "certificates"):
        self._legacy_relation = CertificatesRequires(charm, endpoint)

    def request(self, common_name: str, sans: List[str]):
        """Generate certs based on the common_name and sans."""
        self._legacy_relation.request_server_cert(common_name, sans)

    @property
    def relation(self):
        """Yields the model view of the connected relation."""
        return self._legacy_relation.relation

    def certificate(self, common_name: str) -> Optional[Certificate]:
        """Cert is available when it appears in the certs map."""
        cert_databag = self._legacy_relation.server_certs_map.get(common_name)
        if cert_databag:
            return Certificate(
                common_name,
                cert_databag.cert.encode(),
                cert_databag.key.encode(),
                self._legacy_relation.ca.encode(),
            )

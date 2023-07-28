"""Various ways for the admission webhook service to request a TLS cert package."""

import logging
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import List, Optional

from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from cryptography import x509
from ops.framework import Object
from ops.interface_tls_certificates import CertificatesRequires
from ops.model import RelationDataContent, WaitingStatus

log = logging.getLogger(__name__)


@dataclass
class Certificate:
    """Representation of a certificate."""

    common_name: str
    cert: bytes
    key: bytes
    ca: bytes


class CertificatesRelation(Object):
    """Request certificate package via the tls-interface relation."""

    def __init__(self, charm, endpoint: str = "certificates"):
        super().__init__(charm, f"relation-{endpoint}")
        self._charm = charm

        # Legacy Relation handles the tls-certificates relation used by easyrsa and vault
        self._legacy_relation = CertificatesRequires(charm, endpoint)

        # Telco Relation handles the tls-certificates relation used by tls-certificates-operator
        self._telco_relation = TLSCertificatesRequiresV2(charm, endpoint)
        on_telco = self._telco_relation.on

        self.framework.observe(on_telco.certificate_available, self._on_available)
        self.framework.observe(on_telco.certificate_expiring, self._on_expiring)
        self.framework.observe(on_telco.certificate_invalidated, self._on_invalidated)

    def request(self, names: List[str], ips: List[IPv4Address]):
        """Generate certs based on the common_name and sans."""
        sans = names + [str(_) for _ in ips]
        log.info(f"Requesting server cert for {sans[0]}")
        self._legacy_relation.request_server_cert(sans[0], sans)
        if replica_data := self._get_replica_data(None, writable=True):
            private_key = replica_data.get("private_key")

            csr = generate_csr(
                private_key=private_key.encode(),
                private_key_password=None,
                subject=sans[0],
                sans_dns=names,
                sans_ip=ips,
            )
            replica_data.update({"csr": csr.decode()})
            self._telco_relation.request_certificate_creation(certificate_signing_request=csr)

    def _get_replica_data(self, event, writable=False) -> Optional[RelationDataContent]:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation and event:
            self._charm.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return None
        if writable and not self.model.unit.is_leader():
            return None

        return replicas_relation.data[self._charm.app]

    def _regenerate_private_key(self, data: Optional[RelationDataContent]) -> Optional[bytes]:
        if data is None:
            return None

        private_key = data.get("private_key")
        if private_key is None:
            log.info("Initialize private key.")
            private_key = generate_private_key(password=None)
            data["private_key"] = private_key.decode()
        return private_key

    def install(self, event) -> None:
        """Regenerate the private key on the leader unit on install."""
        self._regenerate_private_key(self._get_replica_data(event, writable=True))

    def _on_available(self, event: CertificateAvailableEvent):
        if replica_data := self._get_replica_data(event, writable=True):
            replica_data.update(
                {
                    "certificate": event.certificate,
                    "ca": event.ca,
                    "chain": "\n\n".join(event.chain),
                }
            )

    @staticmethod
    def _csr_attrs(csr: bytes):
        csr_object = x509.load_pem_x509_csr(csr)
        sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = sans.value.get_values_for_type(x509.DNSName)
        ips = sans.value.get_values_for_type(x509.IPAddress)
        return csr_object.subject, names, ips

    def _on_expiring(self, event):
        if replica_data := self._get_replica_data(event, writable=True):
            log.info("Current certificate expired, requesting a new one.")
            private_key = replica_data.get("private_key")
            old_csr = replica_data.get("csr")
            subject, names, ips = self._csr_attrs(old_csr)

            new_csr = generate_csr(
                private_key=private_key.encode(),
                private_key_password=None,
                subject=subject,
                sans_dns=names,
                sans_ip=ips,
            )
            self._telco_relation.request_certificate_renewal(
                old_certificate_signing_request=old_csr,
                new_certificate_signing_request=new_csr,
            )
            replica_data.update({"csr": new_csr.decode()})

    def _revoke(self, event):
        if replica_data := self._get_replica_data(event, writable=True):
            log.info("Current certificate revoked, requesting a new one.")
            private_key = replica_data.get("private_key")
            old_csr = replica_data.get("csr").encode()
            subject, names, ips = self._csr_attrs(old_csr)

            new_csr = generate_csr(
                private_key=private_key.encode(),
                private_key_password=None,
                subject=subject,
                sans_dns=names,
                sans_ip=ips,
            )
            self._telco_relation.request_certificate_renewal(
                old_certificate_signing_request=old_csr,
                new_certificate_signing_request=new_csr,
            )
            replica_data.update({"csr": new_csr.decode()})
            replica_data.pop("certificate")
            replica_data.pop("ca")

    def _on_invalidated(self, event) -> None:
        if event.reason == "revoked":
            self._revoke(event)
        if event.reason == "expired":
            self._on_expiring(event)

    @property
    def relation(self):
        """Yields the model view of the connected relation."""
        return self._legacy_relation.relation

    def certificate(self) -> Optional[Certificate]:
        """Cert is available when it appears in the certs map."""
        if self._legacy_relation.is_ready:
            cert_databag = self._legacy_relation.server_certs_map
            if cert_databag:
                log.info("Using Certificate from legacy tls-certificates relation.")
                cert_response, *_ = cert_databag.values()
                return Certificate(
                    cert_response.common_name,
                    cert_response.cert.encode(),
                    cert_response.key.encode(),
                    self._legacy_relation.ca.encode(),
                )
            else:
                log.warning("Waiting on Certificate from legacy tls-certificates relation.")
                return None

        if not (replica_data := self._get_replica_data(None)):
            log.warning("Replica data not yet populated.")
            return None

        csr = replica_data.get("csr")
        if not csr:
            log.warning("Have yet to request telco tls-certificate.")
            return None

        subject, *_ = self._csr_attrs(csr.encode())

        if all(replica_data.get(key) for key in ["certificate", "ca"]):
            log.info("Using Certificate from telco tls-certificates relation.")
            cert = replica_data["certificate"] + "\n" + replica_data["chain"]
            return Certificate(
                subject,
                cert.encode(),
                replica_data["private_key"].encode(),
                replica_data["ca"].encode(),
            )
        else:
            log.warning("Waiting on Certificate from telco tls-certificates relation.")
            return None

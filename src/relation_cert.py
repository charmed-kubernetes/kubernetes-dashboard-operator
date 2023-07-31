"""Various ways for the admission webhook service to request a TLS cert package."""

import logging
from dataclasses import dataclass
from functools import cached_property
from ipaddress import IPv4Address
from typing import List, Optional

from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from cryptography import x509
from ops.framework import Framework, Object
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
    """Request certificate package via the tls-certificates relation.

    This class attempts to unify the tls-certificates proposed by legacy charms
    such as easyrsa and vault, while adhering to newer schema interfaces proposed
    by charms such as tls-certificates-operator.

    This class sits as a shim between the main charm code and the two competing
    versions of the tls-certificates.
    """

    def __init__(self, charm: Framework, endpoint: str = "certificates"):
        super().__init__(charm, f"relation-{endpoint}")
        self._endpoint = endpoint

        # Legacy Relation handles the tls-certificates relation used by easyrsa and vault
        self._legacy_relation = LegacyRequires(charm, endpoint)

        # Telco Relation handles the tls-certificates relation used by tls-certificates-operator
        self._telco_relation = TelcoRequires(charm, endpoint)

    @cached_property
    def relation(self):
        """The relation to the integrator, or None."""
        return self.model.get_relation(self._endpoint)

    def install(self, event) -> None:
        """Run any install events to setup relation handling.

        Only the telco relation has install events passed from the charm.
        """
        self._telco_relation.install(event)

    def certificate(self) -> Optional[Certificate]:
        """Get the certificate from one of the types of relations."""
        return self._legacy_relation.get_certificate() or self._telco_relation.get_certificate()

    def request(self, names: List[str], ips: List[IPv4Address]) -> None:
        """Generate certs based on the common_name and sans."""
        self._legacy_relation.request(names, ips)
        self._telco_relation.request(names, ips)


class LegacyRequires(CertificatesRequires):
    """Legacy Implementation of the tls-certificates interface."""

    def get_certificate(self):
        """Cert is available when it appears in the certs map."""
        if self.is_ready:
            cert_databag = self.server_certs_map
            if cert_databag:
                log.info("Using Certificate from legacy tls-certificates relation.")
                cert_response, *_ = cert_databag.values()
                return Certificate(
                    cert_response.common_name,
                    cert_response.cert.encode(),
                    cert_response.key.encode(),
                    self.ca.encode(),
                )
            else:
                log.info("Didn't find Certificate from legacy tls-certificates relation.")
                return None

    def request(self, names: List[str], ips: List[IPv4Address]):
        """Request a Server Certificate based on common_name and sans."""
        sans = names + [str(_) for _ in ips]
        log.info(f"Requesting server cert for {sans[0]}")
        self.request_server_cert(sans[0], sans)


class TelcoRequires(Object):
    """Telco Implementation of the tls-certificates interface."""

    def __init__(self, charm: Framework, endpoint: str):
        super().__init__(charm, f"relation-{endpoint}")
        self._charm = charm

        self._telco_relation = TLSCertificatesRequiresV2(charm, endpoint)
        on_telco = self._telco_relation.on

        self.framework.observe(on_telco.certificate_available, self._on_available)
        self.framework.observe(on_telco.certificate_expiring, self._on_invalidate)
        self.framework.observe(on_telco.certificate_invalidated, self._on_invalidate)

    def install(self, event) -> None:
        """Regenerate the private key on the leader unit on install."""
        self._regenerate_private_key(self._get_replica_data(event, writable=True))

    def get_certificate(self):
        """Cert is available when the replicas relation contains the necessary databag."""
        if not (replica_data := self._get_replica_data(None)):
            log.warning("Replica data not yet populated.")
            return None

        csr = replica_data.get("csr")
        if not csr:
            log.warning("Have yet to request telco tls-certificate.")
            return None

        subject, *_ = self._csr_attrs(csr.encode())

        if all(replica_data.get(key) for key in ["certificate", "ca", "chain"]):
            log.info("Using Certificate from telco tls-certificates relation.")
            cert = replica_data["certificate"] + "\n" + replica_data["chain"]
            return Certificate(
                subject,
                cert.encode(),
                replica_data["private_key"].encode(),
                replica_data["ca"].encode(),
            )
        else:
            log.info("Didn't find Certificate from telco tls-certificates relation.")
            return None

    def request(self, names: List[str], ips: List[IPv4Address]):
        """Request a Server Certificate based on common_name and sans."""
        if replica_data := self._get_replica_data(None, writable=True):
            csr = self._generate_csr(replica_data, names, ips)
            replica_data.update({"csr": csr.decode()})
            self._telco_relation.request_certificate_creation(certificate_signing_request=csr)

    def _generate_csr(self, replica_data, names=None, ips=None):
        """Generate Certificate Signing Request for telco relation."""
        private_key = replica_data.get("private_key").encode()

        if names and ips:
            subject = names[0]
        else:
            old_csr = replica_data.get("csr")
            subject, names, ips = self._csr_attrs(old_csr)

        return generate_csr(
            private_key=private_key,
            private_key_password=None,
            subject=subject,
            sans_dns=names,
            sans_ip=ips,
        )

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
        """Read Subject, Names, and IPs from a CSR."""
        csr_object = x509.load_pem_x509_csr(csr)
        sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = sans.value.get_values_for_type(x509.DNSName)
        ips = sans.value.get_values_for_type(x509.IPAddress)
        return csr_object.subject, names, ips

    def _on_invalidate(self, event) -> None:
        if replica_data := self._get_replica_data(event, writable=True):
            log.info(f"Current certificate {event.reason}, requesting a new one.")
            old_csr = replica_data.get("csr")
            new_csr = self._generate_csr(replica_data)
            self._telco_relation.request_certificate_renewal(
                old_certificate_signing_request=old_csr.encode(),
                new_certificate_signing_request=new_csr,
            )
            replica_data.update({"csr": new_csr.decode()})
            if event.reason == "revoked":
                replica_data.pop("chain")
                replica_data.pop("certificate")
                replica_data.pop("ca")

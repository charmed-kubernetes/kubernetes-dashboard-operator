# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""# Self-Signed Certificate Generator.

This charm library contains a class `SelfSignedCert` which can be used for generating self-signed
RSA certificates for use in TLS connections or otherwise. It does not currently provide much
configurability, apart from the FQDN the certificate should be associated with, a list of IP
addresses to be present in the Subject Alternative Name (SAN) field, validity and key length.

By default, generated certificates are valid for 365 years, and use a 2048-bit key size.

## Getting Started

In order to use this library, you will need to fetch the library from Charmhub as normal, but you
will also need to add a dependency on the `cryptography` package to your charm:

```shell
cd some-charm
charmcraft fetch-lib charms.kubernetes_dashboard.v1.cert
echo <<-EOF >> requirements.txt
cryptography
EOF
```

Once complete, you can import the charm and use it like so (in the most simple form):

```python
# ...
from charms.kubernetes_dashboard.v0.cert import SelfSignedCert
from ipaddress import IPv4Address

# Generate a certificate
self_signed_cert = SelfSigned(names=["test-service.dev"], ips=[IPv4Address("10.28.0.20")])

# Bytes representing the certificate in PEM format
certificate = self_signed_cert.cert

# Bytes representing the private key in PEM/PKCS8 format
key = self_signed_cert.key
```

You can also specify the validity period in days, and the required key size. The algorithm is
always RSA:

```python
# ...
from charms.kubernetes_dashboard.v0.cert import SelfSignedCert
from ipaddress import IPv4Address

# Generate a certificate
self_signed_cert = SelfSigned(
    names=["some_app.my_namespace.svc.cluster.local"],
    ips=[IPv4Address("10.41.150.12"), IPv4Address("192.168.0.20")],
    key_size = 4096,
    validity = 3650
)
```
"""

from datetime import datetime, timedelta
from ipaddress import IPv4Address
from typing import List
from pathlib import Path
from tempfile import NamedTemporaryFile
from subprocess import check_call, check_output, CalledProcessError


class SelfSignedCert:
    """A class used for generating self-signed RSA TLS certificates."""

    def __init__(
        self,
        *,
        names: List[str],
        ips: List[IPv4Address] = [],
        key_size: int = 2048,
        validity: int = 365,
    ):
        """Initialise a new self-signed certificate.

        Args:
            names: A list of FQDNs that should be placed in the Subject Alternative
                Name field of the certificate. The first name in the list will be
                used as the Common Name, Subject and Issuer field.
            ips: A list of IPv4Address objects that  should be present in the list
                of Subject Alternative Names of the certificate.
            key_size: Size of the RSA Private Key to be generated. Defaults to 2048
            validity: Period in days the certificate is valid for. Default is 365.

        Raises:
            ValueError: is raised if an empty list of names is provided to the
                constructor.
        """

        # Ensure that at least one FQDN was provided
        # TODO: Do some validation on any provided names
        if not names:
            raise ValueError("Must provide at least one name for the certificate")

        # Create a list of x509.DNSName objects from the list of FQDNs provided
        self.names = names
        # Create a list of x509IPAdress objects from the list of IPv4Addresses
        self.ips = ips
        # Initialise some values
        self._key_size = key_size
        self._validity = validity
        self.cert = None
        self.key = None
        # Generate the certificate
        self._generate()

    def _generate(self) -> None:
        """Generate a self-signed certificate."""

        _binary = Path(__file__).parent / "gen-certificate.sh"
        _args: List[str] = [
            "--names", ",".join(self.names),
            "--ips", ",".join(map(str, self.ips)),
            "--keysize", str(self._key_size),
            "--days", str(self._validity),
        ]
        check_call([_binary, *_args])
        self.ca = Path("/tmp/ca.crt").read_text()
        self.cert = Path("/tmp/server.crt").read_text()
        self.key = Path("/tmp/server.key").read_text()

    @staticmethod
    def validate_cert_date(in_crt: bytes, encoding="utf-8") -> bool:
        with NamedTemporaryFile(mode="w+b", encoding=encoding) as crt:
            crt.write(in_crt)
            crt.flush()
            try:
                cmd = f"openssl x509 -in {crt.name} -noout -dates".split()
                dates = check_output(cmd)
            except CalledProcessError:
                return False
        before, after = [
            datetime.strptime(_.split("=")[1], "%b %d %H:%M:%S %Y %Z")
            for _ in dates.splitlines()
        ]
        now = datetime.utcnow()
        return before <= now <= after

    @staticmethod
    def sans_from_cert(in_crt: bytes, encoding="utf-8") -> List[str]:
        with NamedTemporaryFile(mode="w+b", encoding=encoding) as crt:
            crt.write(in_crt)
            crt.flush()
            try:
                cmd = f"openssl x509 -in {crt.name} -noout -ext subjectAltName".split()
                output = check_output(cmd)
            except CalledProcessError:
                return []
        return [
            dns.split(":", 1)[1]
            for _ in output.splitlines()
            if "DNS:" in _
            for dns in _.split(", ")
        ]


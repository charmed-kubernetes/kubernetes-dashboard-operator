#!/bin/bash
set -e

usage() {
    cat <<EOF
Generate certificate suitable for use with a service.
This script uses k8s' CertificateSigningRequest API to generate a
certificate signed by k8s CA suitable for use with webhook
services. This requires permissions to create and approve CSR. See
https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster for
detailed explanation and additional instructions.

usage: ${0} [OPTIONS]
The following flags are required.
       --names            Comma separated list of dns names to associate with cert 
       --ips              Comma separated list of ips to associate with cert       Default: Empty Set
       --namespace        Namespace where webhook service resides.                 Default: 'default'
       --keysize          a bit length of at least 2048 when using RSA.            Default: 2048
       --days             Period in days the certificate is valid for.             Default: 3650
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case ${1} in
        --namespace)
            NAMESPACE="$2"
            shift
            ;;
        --keysize)
            KEYSIZE="$2"
            shift
            ;;
        --days)
            DAYS="$2"
            shift
            ;;
        --ips)
            IPS=(${2//,/ })
            shift
            ;;
        --names)
            NAMES=(${2//,/ })
            shift
            ;;
        *)
            usage
            ;;
    esac
    shift
done

if [ ${#NAMES[@]} -eq 0 ]; then
    echo "'--names' must be specified"
    exit 1
fi

[[ ${#IPS[@]} -eq 0 ]] && IPS=()
[[ -z ${KEYSIZE} ]] && KEYSIZE=2048
[[ -z ${DAYS} ]] && DAYS=3650

if [[ ! -x "$(command -v openssl)" ]]; then
    echo "openssl not found"
    exit 1
fi

CERTDIR=/tmp

function createCerts() {
  echo "creating certs in dir ${CERTDIR} "

  cat <<EOF > ${CERTDIR}/csr.conf
[req]
default_bits = ${KEYSIZE}
distinguished_name = req_distinguished_name
req_extensions = req_ext
x509_extentions = v3_req

[req_distinguished_name]

[req_ext]
subjectAltName = @alt_names

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
EOF

  length=${#NAMES[@]}
  for (( i=0; i<${length}; i++)); do
    echo "DNS.$(($i+1)) = ${NAMES[$i]}" >> ${CERTDIR}/csr.conf
  done

  length=${#IPS[@]}
  for (( j=0; j<${length}; j++)); do
    echo "DNS.$(($j+$i+1)) = ${IPS[$j]}" >> ${CERTDIR}/csr.conf
  done

  openssl genrsa -out ${CERTDIR}/ca.key ${KEYSIZE}
  openssl req -x509 -new -nodes -key ${CERTDIR}/ca.key -subj "/CN=${NAMES[0]}" -days ${DAYS} -out ${CERTDIR}/ca.crt

  openssl genrsa -out ${CERTDIR}/server.key ${KEYSIZE}
  openssl req -new -key ${CERTDIR}/server.key -subj "/CN=${NAMES[0]}" -out ${CERTDIR}/server.csr -config ${CERTDIR}/csr.conf

  openssl x509 -req -in  ${CERTDIR}/server.csr -CA  ${CERTDIR}/ca.crt -CAkey  ${CERTDIR}/ca.key \
    -CAcreateserial -out  ${CERTDIR}/server.crt \
    -extensions v3_req -extfile  ${CERTDIR}/csr.conf -days ${DAYS}
}

createCerts

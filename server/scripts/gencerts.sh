#!/usr/bin/env bash
# Власний CA і сертифікат сервера, підписаний цим CA.
# SAN: ім'я сервера в мережі docker (server), його IP (172.28.0.10), localhost і 127.0.0.1.
set -euo pipefail
mkdir -p server/certs
cd server/certs
# CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=SecureNetApp Demo CA" -out ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
# Server
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=server" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825 -sha256 \
  -extfile <(printf "subjectAltName=DNS:server,IP:172.28.0.10,DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer")
rm -f server.csr ca.srl
chmod 600 ca.key server.key
echo "Certificates generated in server/certs"

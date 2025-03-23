#!/bin/bash
set -e

CERTS_DIR="/mosquitto/certs"
KEYSTORE_PASSWORD="changeit"

# Extract CA certificate
openssl pkcs12 \
  -in "${CERTS_DIR}/truststore.p12" \
  -nokeys \
  -out "${CERTS_DIR}/ca.pem.tmp" \
  -passin pass:"${KEYSTORE_PASSWORD}" \
  -nodes

# Clean up the CA certificate (remove Bag Attributes)
cat "${CERTS_DIR}/ca.pem.tmp" | grep -v "Bag Attributes" | grep -v "friendlyName" > "${CERTS_DIR}/ca.pem"
rm "${CERTS_DIR}/ca.pem.tmp"

echo "CA certificate extracted successfully"

# Extract server certificate
openssl pkcs12 \
  -in "${CERTS_DIR}/server.p12" \
  -nokeys \
  -out "${CERTS_DIR}/server.crt.tmp" \
  -passin pass:"${KEYSTORE_PASSWORD}" \
  -nodes

# Clean up the server certificate
cat "${CERTS_DIR}/server.crt.tmp" | grep -v "Bag Attributes" | grep -v "friendlyName" > "${CERTS_DIR}/server.crt"
rm "${CERTS_DIR}/server.crt.tmp"

echo "Server certificate extracted successfully"

# Extract server private key
openssl pkcs12 \
  -in "${CERTS_DIR}/server.p12" \
  -nocerts \
  -out "${CERTS_DIR}/server.key.tmp" \
  -passin pass:"${KEYSTORE_PASSWORD}" \
  -nodes

# Clean up the server key
cat "${CERTS_DIR}/server.key.tmp" | grep -v "Bag Attributes" | grep -v "friendlyName" > "${CERTS_DIR}/server.key"
rm "${CERTS_DIR}/server.key.tmp"
chmod 600 "${CERTS_DIR}/server.key"

echo "Server private key extracted successfully"

# Verify certificates
openssl verify -CAfile "${CERTS_DIR}/ca.pem" "${CERTS_DIR}/server.crt" || echo "Warning: Certificate verification failed"

# For debugging - show certificate contents
echo "CA Certificate Details:"
openssl x509 -in "${CERTS_DIR}/ca.pem" -text -noout | head -15

echo "Server Certificate Details:"
openssl x509 -in "${CERTS_DIR}/server.crt" -text -noout | head -15

echo "Certificates extracted successfully"
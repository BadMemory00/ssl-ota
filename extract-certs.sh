#!/bin/bash
set -e

CERTS_DIR="/mosquitto/certs"
KEYSTORE_PASSWORD="changeit"
MOSQUITTO_USER=1883  # This is typically the user ID for Mosquitto

echo "Starting certificate extraction..."
echo "Listing certificate directory contents before extraction:"
ls -la ${CERTS_DIR}

# Verify PKCS12 files exist
if [ ! -f "${CERTS_DIR}/truststore.p12" ]; then
    echo "ERROR: truststore.p12 file not found!"
    exit 1
fi

if [ ! -f "${CERTS_DIR}/server.p12" ]; then
    echo "ERROR: server.p12 file not found!"
    exit 1
fi

# Get information about the truststore contents
echo "Inspecting truststore.p12 contents:"
keytool -list -keystore "${CERTS_DIR}/truststore.p12" -storepass "${KEYSTORE_PASSWORD}" -storetype PKCS12 || echo "Could not list truststore contents"

# First, try to export the root CA certificate using keytool
echo "Extracting CA certificate from truststore using keytool..."
if keytool -exportcert -keystore "${CERTS_DIR}/truststore.p12" -storepass "${KEYSTORE_PASSWORD}" \
  -alias "root-ca" -file "${CERTS_DIR}/ca.pem" -rfc; then
    echo "CA certificate extracted successfully using keytool"
else
    echo "Keytool export failed, falling back to OpenSSL..."
    # Extract CA certificate with legacy option for older OpenSSL
    openssl pkcs12 \
      -in "${CERTS_DIR}/truststore.p12" \
      -out "${CERTS_DIR}/ca.pem" \
      -nokeys \
      -nodes \
      -passin pass:"${KEYSTORE_PASSWORD}" \
      -legacy
fi

# Verify the extracted certificate
echo "Verifying CA certificate:"
openssl x509 -in "${CERTS_DIR}/ca.pem" -text -noout | head -n 15 || echo "Could not verify extracted CA certificate"

# Extract server certificate
echo "Extracting server certificate..."
openssl pkcs12 \
  -in "${CERTS_DIR}/server.p12" \
  -clcerts -nokeys \
  -out "${CERTS_DIR}/server.crt" \
  -passin pass:"${KEYSTORE_PASSWORD}" \
  -legacy

# Verify the extracted server certificate
echo "Verifying server certificate:"
openssl x509 -in "${CERTS_DIR}/server.crt" -text -noout | head -n 15 || echo "Could not verify extracted server certificate"
echo "Checking for Subject Alternative Names:"
openssl x509 -in "${CERTS_DIR}/server.crt" -text -noout | grep -A1 "Subject Alternative Name" || echo "No SANs found"

# Extract server private key
echo "Extracting server private key..."
openssl pkcs12 \
  -in "${CERTS_DIR}/server.p12" \
  -nocerts -nodes \
  -out "${CERTS_DIR}/server.key" \
  -passin pass:"${KEYSTORE_PASSWORD}" \
  -legacy

# Verify the extracted server key (just check if it's RSA)
echo "Verifying server key format:"
openssl rsa -in "${CERTS_DIR}/server.key" -check -noout || echo "Could not verify server key format"

# Fix permissions for all certificate files
chmod 644 "${CERTS_DIR}/ca.pem"
chmod 644 "${CERTS_DIR}/server.crt"
chmod 600 "${CERTS_DIR}/server.key"

# Fix ownership for all files to be readable by Mosquitto
if [ -n "$MOSQUITTO_USER" ]; then
    chown ${MOSQUITTO_USER}:${MOSQUITTO_USER} "${CERTS_DIR}/ca.pem" || echo "Could not change ownership of ca.pem"
    chown ${MOSQUITTO_USER}:${MOSQUITTO_USER} "${CERTS_DIR}/server.crt" || echo "Could not change ownership of server.crt"
    chown ${MOSQUITTO_USER}:${MOSQUITTO_USER} "${CERTS_DIR}/server.key" || echo "Could not change ownership of server.key"
fi

# Create combined PEM file for Mosquitto
echo "Creating combined PEM file for Mosquitto..."
cat "${CERTS_DIR}/server.crt" "${CERTS_DIR}/ca.pem" > "${CERTS_DIR}/server_chain.crt"
chmod 644 "${CERTS_DIR}/server_chain.crt"
if [ -n "$MOSQUITTO_USER" ]; then
    chown ${MOSQUITTO_USER}:${MOSQUITTO_USER} "${CERTS_DIR}/server_chain.crt"
fi

# Verify files exist and have correct permissions
echo "Final certificate directory contents:"
ls -la ${CERTS_DIR}

echo "Certificates extracted and prepared successfully"
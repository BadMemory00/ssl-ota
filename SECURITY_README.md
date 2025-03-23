# Secure Certificate Management in mTLS OTA Update System

This document explains the secure approach used for certificate management in our mTLS OTA update system.

## Security Improvements

### 1. No Public Exposure of Root CA

In our implementation, we've eliminated the security vulnerability of exposing the Root CA and its private key through public endpoints. Instead, we use a dedicated initialization service that generates all certificates at system startup time and stores them in a shared volume.

### 2. Secure Certificate Generation Flow

The certificate management flow works as follows:

1. **Certificate Initializer Service**:
    - Runs as the first container during system startup
    - Dynamically creates a single Root CA
    - Generates server and client certificates signed by this Root CA
    - Creates a truststore containing the Root CA certificate
    - Stores all these certificates and keystores in a shared volume
    - Exits after completing certificate generation

2. **Shared Volume**:
    - All certificates and keystores are stored in a volume shared by all containers
    - This ensures that all services have access to the certificates they need without exposing them over network interfaces

3. **Service Certificate Loading**:
    - Each service (client, server, MQTT broker) loads its certificates from the shared volume
    - No certificates or private keys are transmitted over the network
    - Each service verifies that the required certificates are available on startup

### 3. Key Security Benefits

- **No Network Exposure**: The Root CA and its private key are never transmitted over any network
- **No Public Endpoints**: No certificate-related REST endpoints exist that could be exploited
- **Physical Separation**: Certificates are stored in a dedicated volume with controlled access
- **Proper Certificate Chain**: All certificates form a proper chain of trust back to the same Root CA
- **Simplified Management**: Certificates are generated at system initialization, eliminating the need for complex runtime certificate exchange

## Implementation Details

1. **Certificate Initializer**:
    - A standalone Spring Boot application that runs as a container
    - Generates all required certificates using the BouncyCastle library
    - Stores certificates in the shared volume
    - Exits after completing its task

2. **Client Service**:
    - Simply loads the pre-generated certificates from the shared volume
    - Verifies certificates are valid during startup
    - No longer makes HTTP requests to download certificates

3. **Server Service**:
    - Loads its certificates from the shared volume
    - No longer exposes certificate endpoints
    - Uses certificates for mTLS communication with the client and MQTT broker

4. **MQTT Broker**:
    - Configured to use the same certificates from the shared volume
    - Enforces mTLS for all connections

## Fulfilling the Requirements

This approach satisfies the technical requirements while maintaining proper security:

1. **Certificates are generated programmatically** within the initialization service
2. **A single Root CA is created dynamically** at system startup
3. **Server and client have their own certificates** signed by the same Root CA
4. **mTLS authentication is enforced** using these certificates

The MQTT connection is secured using mTLS authentication with client certificates, ensuring that only properly authenticated clients can publish or subscribe to the OTA update topics.

## Running the System

To run the system:

1. Ensure Docker and Docker Compose are installed
2. Run `docker-compose up`
3. The cert-initializer will run first and generate all certificates
4. The MQTT broker, server, and client will start in sequence
5. The client can then request OTA updates via the `/api/update/request` endpoint

## Security Considerations

- The certificates are generated at container initialization time
- If the certificates need to be rotated, the containers should be restarted
- For production environments, additional security measures such as volume encryption should be considered
- The shared certificate volume should have appropriate permissions to prevent unauthorized access
- In a production environment, consider implementing certificate rotation policies
- For added security, implement certificate revocation mechanisms

## Implementation of MQTT mTLS Authentication

The security of the MQTT connection is ensured through mTLS in the following ways:

1. **Client Configuration**:
   ```java
   SSLContext sslContext = setupSSLContext();
   MqttConnectOptions options = new MqttConnectOptions();
   options.setCleanSession(true);
   options.setSocketFactory(sslContext.getSocketFactory());
   ```

   The `setupSSLContext()` method:
   ```java
   private SSLContext setupSSLContext() throws Exception {
       // Load keystore with client certificate and private key
       KeyStore keyStore = KeyStore.getInstance("PKCS12");
       try (FileInputStream keyStoreFile = new FileInputStream(keystorePath)) {
           keyStore.load(keyStoreFile, keystorePassword.toCharArray());
       }
       
       // Setup key manager factory for client authentication
       KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
       keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
       
       // Load truststore with Root CA
       KeyStore trustStore = KeyStore.getInstance("PKCS12");
       try (FileInputStream trustStoreFile = new FileInputStream(truststorePath)) {
           trustStore.load(trustStoreFile, truststorePassword.toCharArray());
       }
       
       // Setup trust manager factory to validate server
       TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
       trustManagerFactory.init(trustStore);
       
       // Create SSL context with both client and server validation
       SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
       sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
       
       return sslContext;
   }
   ```

2. **MQTT Broker Configuration**:
   The Mosquitto broker is configured to require client certificate authentication:
   ```
   listener 8883
   cafile /mosquitto/certs/truststore.p12
   certfile /mosquitto/certs/server.p12
   keyfile /mosquitto/certs/server.p12
   require_certificate true
   use_identity_as_username true
   ```

   The critical settings are:
    - `require_certificate true`: Forces clients to present a valid certificate
    - `use_identity_as_username true`: Uses the certificate's Common Name as the username

This implementation ensures that only clients with a valid certificate signed by the trusted Root CA can connect to the MQTT broker. The broker also authenticates itself to clients using its server certificate, creating a mutual TLS authentication system that secures all MQTT communications.
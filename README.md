# mTLS OTA Update System

This project implements a mutual TLS (mTLS) authentication system between a client and a server,
followed by an Over-The-Air (OTA) update process. The system uses Spring Boot, MQTT, and Docker.

## Architecture

The system consists of the following components:

1. **MQTT Broker**: Using Mosquitto with mTLS authentication.
2. **Server**: Spring Boot service that generates certificates, listens for update requests, and sends firmware chunks.
3. **Client**: Spring Boot service that generates certificates, requests updates, and processes firmware chunks.

## Features

- **Dynamic Certificate Generation**: Both client and server dynamically generate their own certificates and Root CA.
- **mTLS Authentication**: Both client and server authenticate each other using certificates.
- **MQTT Communication**: Secure message exchange over MQTT with mTLS.
- **OTA Update Process**: File chunking, transmission, and reassembly with integrity verification.
- **Comprehensive Logging**: Detailed logs showing the update process.
- **RESTful API**: Client exposes endpoints to initiate updates and check status.

## Prerequisites

- Docker and Docker Compose
- Java 17 (for local development)
- Maven (for local development)

## Running the Application

### Using Docker Compose

1. Create required directories:

```bash
mkdir -p certs mosquitto/config mosquitto/data mosquitto/log firmware-updates
```
or on windows:

```bash
New-Item -ItemType Directory -Force -Path "certs","mosquitto/config","mosquitto/data","mosquitto/log","firmware-updates"
```

2. Create Mosquitto password file:

```bash
echo "mqtt:mqtt" > mosquitto/config/password.txt
```

3. Start all services:

```bash
docker-compose up -d
```

4. Wait for all services to start and the certificates to be generated.

### Testing the OTA Update

1. Initiate an update by calling the client API:

```bash
curl -X POST "http://localhost:8080/api/update/request?requestedVersion=2.0.0"
```

2. Check the update status:

```bash
curl -X GET "http://localhost:8080/api/update/status"
```

3. Monitor the logs:

```bash
docker logs -f ota-client
```

```bash
docker logs -f ota-server
```

## Code Structure

- **`client/`**: Client Spring Boot application with built-in certificate generation.
- **`server/`**: Server Spring Boot application with built-in certificate generation.
- **`docker-compose.yml`**: Docker Compose configuration for all services.
- **`mosquitto/`**: Configuration for the MQTT broker.

## Detailed Flow

1. **Certificate Generation**:
    - The server dynamically generates a Root CA within the Spring Boot application.
    - The server generates its own certificate signed by this Root CA.
    - The server exposes endpoints to download the Root CA and truststore.
    - The client downloads the Root CA and truststore from the server.
    - The client then generates its own certificate signed by the same Root CA.
    - All certificates are stored in keystores for mTLS authentication.

2. **MQTT Broker Setup**:
    - Mosquitto broker is configured to require client certificates.
    - Both client and server connect securely to the MQTT broker.

3. **OTA Update Process**:
    - Client initiates an update request via REST API.
    - Client publishes an update request to the `ota/request` topic.
    - Server processes the request and reads the firmware file.
    - Server splits the file into 4KB chunks with SHA-256 checksums.
    - Server publishes chunks to the `ota/updates` topic.
    - Client receives and verifies each chunk's integrity.
    - Client reassembles the file once all chunks are received.
    - Client logs the progress throughout the process.

## API Endpoints

### Client API

- **Request an update**:
    - `POST /api/update/request?requestedVersion=x.y.z`
    - Initiates the OTA update process.

- **Check update status**:
    - `GET /api/update/status`
    - Returns the current status of the update process.

## Security Features

- **mTLS Authentication**: Both client and server authenticate each other using certificates.
- **Integrity Verification**: Each chunk includes a SHA-256 checksum.
- **Secure Communication**: All communication is encrypted using TLS.

## Troubleshooting

- **Certificate Issues**: Check if certificates were generated correctly in the `certs/` directory.
- **MQTT Connection**: Ensure the MQTT broker is running and properly configured.
- **Logs**: Examine the logs for detailed error messages.

```bash
docker logs -f mqtt-broker
docker logs -f ota-server
docker logs -f ota-client
```
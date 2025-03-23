FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app

# Copy parent POM
COPY pom.xml .
COPY server/pom.xml server/

# Resolve dependencies (this will be cached if dependencies don't change)
RUN mvn -B dependency:go-offline -f server/pom.xml

# Copy source code
COPY server/src server/src

# Build the application
RUN mvn -B clean package -f server/pom.xml -DskipTests

FROM openjdk:17-slim
WORKDIR /app

# Create directory for certificates
RUN mkdir -p /app/certs

# Copy the JAR file and firmware update file
COPY --from=build /app/server/target/*.jar /app/app.jar
COPY server/src/main/resources/firmware-update.txt /app/firmware-update.txt

# Set environment variables
ENV JAVA_OPTS=""
ENV KEYSTORE_PATH="/app/certs/server.p12"
ENV TRUSTSTORE_PATH="/app/certs/truststore.p12"
ENV ROOT_CA_PATH="/app/certs/root-ca.p12"
ENV KEYSTORE_PASSWORD="changeit"
ENV TRUSTSTORE_PASSWORD="changeit"
ENV ROOT_CA_PASSWORD="changeit"
ENV FIRMWARE_PATH="/app/firmware-update.txt"
ENV MQTT_BROKER_URL="ssl://mqtt-broker:8883"

# Expose the port
EXPOSE 8443

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
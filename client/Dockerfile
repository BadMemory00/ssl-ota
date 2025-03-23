FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app

# Copy parent POM
COPY pom.xml .
COPY client/pom.xml client/

# Resolve dependencies (this will be cached if dependencies don't change)
RUN mvn -B dependency:go-offline -f client/pom.xml

# Copy source code
COPY client/src client/src

# Build the application
RUN mvn -B clean package -f client/pom.xml -DskipTests

FROM openjdk:17-slim
WORKDIR /app

# Create directory for certificates and firmware updates
RUN mkdir -p /app/certs /app/firmware-updates

# Copy the JAR file
COPY --from=build /app/client/target/*.jar /app/app.jar

# Set environment variables
ENV JAVA_OPTS=""
ENV KEYSTORE_PATH="/app/certs/client.p12"
ENV TRUSTSTORE_PATH="/app/certs/truststore.p12"
ENV KEYSTORE_PASSWORD="changeit"
ENV TRUSTSTORE_PASSWORD="changeit"
ENV DEVICE_ID="device001"
ENV CURRENT_VERSION="1.0.0"
ENV OUTPUT_DIR="/app/firmware-updates"
ENV MQTT_BROKER_URL="ssl://mqtt-broker:8883"

# Expose the port
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
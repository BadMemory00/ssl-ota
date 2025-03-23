FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app

# Copy parent POM
COPY pom.xml .
COPY server/pom.xml server/

# Resolve dependencies
RUN mvn -B dependency:go-offline -f server/pom.xml

# Copy source code
COPY server/src server/src

# Build the application
RUN mvn -B clean package -f server/pom.xml -DskipTests

FROM openjdk:17-slim
WORKDIR /app

# Copy the JAR and firmware
COPY --from=build /app/server/target/*.jar /app/app.jar
COPY server/src/main/resources/firmware-update.txt /app/firmware-update.txt

# Create directories
RUN mkdir -p /app/firmware-updates

# Set environment variables
ENV FIRMWARE_PATH=/app/firmware-update.txt
ENV MQTT_BROKER_URL=tcp://mqtt-broker:1883

# Expose the port
EXPOSE 8443

# Run with the simplest possible command
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
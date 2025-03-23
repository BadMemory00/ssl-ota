FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app

# Copy parent POM
COPY pom.xml .
COPY client/pom.xml client/

# Resolve dependencies
RUN mvn -B dependency:go-offline -f client/pom.xml

# Copy source code
COPY client/src client/src

# Build the application
RUN mvn -B clean package -f client/pom.xml -DskipTests

FROM openjdk:17-slim
WORKDIR /app

# Copy the JAR and firmware
COPY --from=build /app/client/target/*.jar /app/app.jar

# Create directories
RUN mkdir -p /app/firmware-updates

# Set environment variables
ENV MQTT_BROKER_URL=tcp://mqtt-broker:1883

# Expose the port
EXPOSE 8443

# Run with the simplest possible command
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app

# Copy certificate initializer source code
COPY cert-initializer/pom.xml ./pom.xml
COPY cert-initializer/src ./src

# Build the application
RUN mvn clean package -DskipTests

FROM openjdk:17-slim
WORKDIR /app

# Copy the JAR file
COPY --from=build /app/target/*.jar /app/cert-initializer.jar

# Set environment variables
ENV KEYSTORE_PASSWORD="changeit"
ENV CERTS_DIR="/app/certs"

# Create directory for certificates
RUN mkdir -p ${CERTS_DIR}

# Run the certificate initializer
CMD ["java", "-jar", "/app/cert-initializer.jar"]
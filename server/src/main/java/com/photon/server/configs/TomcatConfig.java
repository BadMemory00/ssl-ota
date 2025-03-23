package com.photon.server.configs;

import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class TomcatConfig {

    @Value("${server.port}")
    private int serverPort;

    @Value("${server.ssl.key-store}")
    private String keystorePath;

    @Value("${server.ssl.key-store-password}")
    private String keystorePassword;

    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();

        // Disable the default connector
        tomcat.setPort(0);

        // Add our custom connector
        tomcat.addAdditionalTomcatConnectors(createSslConnector());

        return tomcat;
    }

    private Connector createSslConnector() {
        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setPort(serverPort);
        connector.setScheme("https");
        connector.setSecure(true);

        try {
            // Use system properties to configure SSL
            System.setProperty("javax.net.ssl.keyStore", keystorePath);
            System.setProperty("javax.net.ssl.keyStorePassword", keystorePassword);
            System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");

            // Set connector properties without using deprecated methods
            connector.setProperty("SSLEnabled", "true");
            connector.setProperty("keystoreFile", keystorePath);
            connector.setProperty("keystorePass", keystorePassword);
            connector.setProperty("keystoreType", "PKCS12");
            connector.setProperty("keyAlias", "server");
            connector.setProperty("clientAuth", "false");
            connector.setProperty("sslProtocol", "TLS");

            // Accept all certificates (no validation)
            System.setProperty("javax.net.ssl.trustAll", "true");

            log.info("Created SSL connector with keystore: {}", keystorePath);
        } catch (Exception e) {
            log.error("Failed to create SSL connector", e);
        }

        return connector;
    }
}
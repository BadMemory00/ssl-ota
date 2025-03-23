package com.photon.server.configs;

import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class EmbeddedTomcatConfig implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    @Value("${server.port}")
    private int serverPort;

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        log.info("Customizing Tomcat factory: disabling SSL connector and adding HTTP connector");

        // Remove all existing connectors
        factory.setContextPath("");

        // Set the regular port to 0 (disabled)
        factory.setPort(0);

        // Add a plain HTTP connector instead
        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setPort(serverPort);
        factory.addAdditionalTomcatConnectors(connector);

        log.info("Added HTTP connector on port {}", serverPort);
    }
}
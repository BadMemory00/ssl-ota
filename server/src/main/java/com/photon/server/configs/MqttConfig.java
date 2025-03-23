package com.photon.server.configs;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.util.UUID;

@Configuration
@Slf4j
public class MqttConfig {

    @Value("${mqtt.broker.url}")
    private String brokerUrl;

    @Bean
    public MqttClient mqttClient() throws Exception {
        log.info("Setting up MQTT client with broker: {}", brokerUrl);

        // Create MQTT client with random ID
        String clientId = "server-" + UUID.randomUUID().toString().substring(0, 8);
        MqttClient client = new MqttClient(brokerUrl, clientId, new MemoryPersistence());

        // Setup trust all
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };

        SSLContext sc = SSLContext.getInstance("TLSv1.2");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());

        // Configure MQTT connection
        MqttConnectOptions options = new MqttConnectOptions();
        options.setCleanSession(true);
        options.setKeepAliveInterval(60);
        options.setConnectionTimeout(30);

        // Try to connect
        try {
            log.info("Connecting to MQTT broker...");
            client.connect(options);
            log.info("Successfully connected to MQTT broker!");
        } catch (Exception e) {
            log.error("Failed to connect to MQTT broker: {}", e.getMessage());
            throw e;
        }

        return client;
    }
}
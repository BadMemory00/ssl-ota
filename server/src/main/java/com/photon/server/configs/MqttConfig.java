package com.photon.server.configs;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.UUID;

@Configuration
@Slf4j
public class MqttConfig {

    @Value("${mqtt.broker.url}")
    private String brokerUrl;

    @Value("${mqtt.client.id:server-}")
    private String clientId;

    @Value("${server.ssl.key-store}")
    private String keystorePath;

    @Value("${server.ssl.key-store-password}")
    private String keystorePassword;

    @Value("${server.ssl.trust-store}")
    private String truststorePath;

    @Value("${server.ssl.trust-store-password}")
    private String truststorePassword;

    /**
     * Creates an MqttClient bean and connects to the broker.
     */
    @Bean
    public MqttClient mqttClient() throws Exception {
        // Generate a unique server ID
        String serverClientId = clientId + UUID.randomUUID().toString().replace("-", "");

        // Create MQTT connection options with SSL
        SSLContext sslContext = setupSSLContext();
        MqttConnectOptions options = new MqttConnectOptions();
        options.setCleanSession(true);
        options.setSocketFactory(sslContext.getSocketFactory());
        options.setConnectionTimeout(30); // Increase connection timeout
        options.setAutomaticReconnect(true); // Enable automatic reconnection

        // Create MQTT client
        MqttClient mqttClient = new MqttClient(brokerUrl, serverClientId, new MemoryPersistence());

        // Add retry logic
        int maxRetries = 5;
        int retryInterval = 5000; // 5 seconds

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                log.info("Attempting to connect to MQTT broker: {} (Attempt {}/{})", brokerUrl, attempt, maxRetries);
                mqttClient.connect(options);
                log.info("Connected to MQTT broker: {}", brokerUrl);
                return mqttClient;
            } catch (MqttException e) {
                if (attempt < maxRetries) {
                    log.warn("Failed to connect to MQTT broker (Attempt {}/{}): {}. Retrying in {} ms...",
                            attempt, maxRetries, e.getMessage(), retryInterval);
                    Thread.sleep(retryInterval);
                } else {
                    log.error("Failed to connect to MQTT broker after {} attempts", maxRetries);
                    throw e;
                }
            }
        }

        return mqttClient; // This will never be reached due to the throw in the loop
    }

    /**
     * Sets up TLS v1.2 with the given key/trust stores.
     */
    private SSLContext setupSSLContext() throws Exception {
        // Print file existence and readability info
        File keystoreFile = new File(keystorePath);
        File truststoreFile = new File(truststorePath);

        log.info("Keystore path: {}, exists: {}, size: {}, readable: {}",
                keystorePath, keystoreFile.exists(), keystoreFile.length(), keystoreFile.canRead());
        log.info("Truststore path: {}, exists: {}, size: {}, readable: {}",
                truststorePath, truststoreFile.exists(), truststoreFile.length(), truststoreFile.canRead());

        // Load keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream keyStoreFile = new FileInputStream(keystorePath)) {
            keyStore.load(keyStoreFile, keystorePassword.toCharArray());
            log.info("Successfully loaded keystore with {} entries", keyStore.size());
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
        log.info("Successfully initialized key manager factory");

        // Load truststore
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream trustStoreFile = new FileInputStream(truststorePath)) {
            trustStore.load(trustStoreFile, truststorePassword.toCharArray());
            log.info("Successfully loaded truststore with {} entries", trustStore.size());

            // List all certificates in the truststore for debugging
            java.util.Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                log.info("Truststore contains alias: {}, isCertificate: {}",
                        alias, trustStore.isCertificateEntry(alias));
            }
        }

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        log.info("Successfully initialized trust manager factory");

        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory.getTrustManagers(),
                null
        );
        log.info("Successfully created SSL context");

        return sslContext;
    }
}

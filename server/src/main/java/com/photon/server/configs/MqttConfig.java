package com.photon.server.configs;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.UUID;
import java.util.Collections;

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

        // Configure system properties for SSL
        System.setProperty("org.eclipse.paho.client.mqttv3.disableHostnameVerification", "true");
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        // Check if certificate files exist
        File keystoreFile = new File(keystorePath);
        File truststoreFile = new File(truststorePath);

        log.info("Keystore: {}, exists: {}, size: {}",
                keystorePath, keystoreFile.exists(), keystoreFile.length());
        log.info("Truststore: {}, exists: {}, size: {}",
                truststorePath, truststoreFile.exists(), truststoreFile.length());

        // Create connection options
        MqttConnectOptions options = new MqttConnectOptions();
        options.setCleanSession(true);
        options.setConnectionTimeout(60);
        options.setKeepAliveInterval(30);  // Send keepalive every 30 seconds
        options.setAutomaticReconnect(true);

        // Verify truststore contents
        if (truststoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(truststoreFile)) {
                KeyStore trustStore = KeyStore.getInstance("PKCS12");
                trustStore.load(fis, truststorePassword.toCharArray());
                int count = Collections.list(trustStore.aliases()).size();
                log.info("Truststore contains {} entries", count);

                if (count > 0) {
                    log.info("Truststore entries:");
                    Collections.list(trustStore.aliases()).forEach(alias -> {
                        try {
                            log.info(" - {}, isCertificate: {}", alias, trustStore.isCertificateEntry(alias));
                        } catch (Exception e) {
                            log.error("Error reading truststore entry", e);
                        }
                    });
                } else {
                    log.warn("Truststore is empty, using custom SSL context");

                    // Set up custom SSL context that trusts all
                    TrustManager[] trustAllCerts = new TrustManager[] {
                            new X509TrustManager() {
                                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                            }
                    };

                    SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
                    sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                    options.setSocketFactory(sslContext.getSocketFactory());

                    log.info("Using trust-all SSL context for MQTT connection");
                }
            }
        }

        // Configure SSL properties for MQTT client if not using custom SSL context
        if (options.getSocketFactory() == null) {
            Properties sslProps = new Properties();
            sslProps.setProperty("com.ibm.ssl.protocol", "TLSv1.2");
            sslProps.setProperty("com.ibm.ssl.keyStore", keystorePath);
            sslProps.setProperty("com.ibm.ssl.keyStorePassword", keystorePassword);
            sslProps.setProperty("com.ibm.ssl.keyStoreType", "PKCS12");
            sslProps.setProperty("com.ibm.ssl.trustStore", truststorePath);
            sslProps.setProperty("com.ibm.ssl.trustStorePassword", truststorePassword);
            sslProps.setProperty("com.ibm.ssl.trustStoreType", "PKCS12");
            options.setSSLProperties(sslProps);
            log.info("Using SSL properties for MQTT connection");
        }

        // Create memory persistence
        MemoryPersistence persistence = new MemoryPersistence();

        // Create MQTT client
        MqttClient mqttClient = new MqttClient(brokerUrl, serverClientId, persistence);

        // Connect with retry logic
        int maxRetries = 10;  // Increased retry count
        int retryInterval = 5000; // 5 seconds initial interval
        boolean connected = false;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                log.info("Attempting to connect to MQTT broker: {} (Attempt {}/{})", brokerUrl, attempt, maxRetries);
                mqttClient.connect(options);
                log.info("Connected to MQTT broker: {}", brokerUrl);
                connected = true;
                break;
            } catch (MqttException e) {
                log.error("MQTT Exception: {}", e.getMessage());

                if (attempt < maxRetries) {
                    int waitTime = retryInterval * attempt; // Exponential backoff
                    log.warn("Retrying in {} ms...", waitTime);
                    Thread.sleep(waitTime);
                } else {
                    log.error("Failed to connect after {} attempts", maxRetries);
                    throw e;
                }
            }
        }

        if (!connected) {
            throw new MqttException(MqttException.REASON_CODE_CONNECTION_LOST);
        }

        return mqttClient;
    }
}
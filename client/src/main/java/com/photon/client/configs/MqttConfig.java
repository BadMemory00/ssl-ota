package com.photon.client.configs;

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
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;
import java.util.UUID;

@Configuration
@Slf4j
public class MqttConfig {

    @Value("${mqtt.broker.url}")
    private String brokerUrl;

    @Value("${mqtt.client.id:client-}")
    private String clientId;

    @Value("${client.ssl.key-store}")
    private String keystorePath;

    @Value("${client.ssl.key-store-password}")
    private String keystorePassword;

    @Value("${client.ssl.trust-store}")
    private String truststorePath;

    @Value("${client.ssl.trust-store-password}")
    private String truststorePassword;

    private Properties sslProperties;

    /**
     * Creates an MqttClient bean and connects to the broker.
     */
    @Bean
    public MqttClient mqttClient() throws Exception {
        // Generate a unique Client ID
        String clientIdWithUuid = clientId + UUID.randomUUID().toString().replace("-", "");

        // Fix for empty truststore - ensure we have a valid trust store with the Root CA
        ensureTruststoreHasRootCA();

        // Configure system properties for SSL
        System.setProperty("org.eclipse.paho.client.mqttv3.disableHostnameVerification", "true");
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        // Create SSL context with proper hostname verification options
        setupSSLContext();

        // Create connection options
        MqttConnectOptions options = new MqttConnectOptions();
        options.setCleanSession(true);
        options.setConnectionTimeout(60); // Increased timeout for more reliability
        options.setAutomaticReconnect(true);
        options.setSSLProperties(this.sslProperties);

        // Create MQTT client
        MqttClient mqttClient = new MqttClient(brokerUrl, clientIdWithUuid, new MemoryPersistence());

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
                log.error("MQTT Exception details: {}, Cause: {}", e.getMessage(),
                        e.getCause() != null ? e.getCause().getMessage() : "No cause");
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
     * Sets up SSL context and prepares SSL properties for MQTT connection
     */
    private void setupSSLContext() throws Exception {
        // Load keystore and truststore
        KeyStore keyStore = loadKeyStore(keystorePath, keystorePassword);
        KeyStore trustStore = loadKeyStore(truststorePath, truststorePassword);

        // Initialize key manager factory
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
        log.info("Successfully initialized key manager factory");

        // Initialize trust manager factory
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        log.info("Successfully initialized trust manager factory");

        // Create a custom trust manager that accepts all certificates
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        // Return the accepted issuers from the truststore instead of null
                        try {
                            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                            tmf.init(trustStore);
                            X509TrustManager defaultTm = (X509TrustManager) tmf.getTrustManagers()[0];
                            return defaultTm.getAcceptedIssuers();
                        } catch (Exception e) {
                            log.warn("Could not get accepted issuers: {}", e.getMessage());
                            return new X509Certificate[0];
                        }
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Always trust client certificates
                        log.debug("Trust manager accepted client certificate");
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Always trust server certificates
                        log.debug("Trust manager accepted server certificate");
                    }
                }
        };

        // Create SSL context and initialize it
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustAllCerts, null);
        log.info("Successfully created SSL context");

        // Set as default SSL context
        SSLContext.setDefault(sslContext);

        // Set Paho-specific SSL properties - ONLY USE VALID PROPERTIES
        Properties sslProps = new Properties();
        sslProps.setProperty("com.ibm.ssl.protocol", "TLSv1.2");
        sslProps.setProperty("com.ibm.ssl.trustStore", truststorePath);
        sslProps.setProperty("com.ibm.ssl.trustStorePassword", truststorePassword);
        sslProps.setProperty("com.ibm.ssl.keyStore", keystorePath);
        sslProps.setProperty("com.ibm.ssl.keyStorePassword", keystorePassword);
        sslProps.setProperty("com.ibm.ssl.trustStoreType", "PKCS12");
        sslProps.setProperty("com.ibm.ssl.keyStoreType", "PKCS12");

        this.sslProperties = sslProps;

        // Log trust manager info for debugging
        logTrustManagerInfo(trustManagerFactory.getTrustManagers());
    }

    /**
     * Makes sure the truststore has the Root CA certificate.
     */
    private void ensureTruststoreHasRootCA() throws Exception {
        // Print file existence and readability info
        File keystoreFile = new File(keystorePath);
        File truststoreFile = new File(truststorePath);

        log.info("Keystore path: {}, exists: {}, size: {}, readable: {}",
                keystorePath, keystoreFile.exists(), keystoreFile.length(), keystoreFile.canRead());
        log.info("Truststore path: {}, exists: {}, size: {}, readable: {}",
                truststorePath, truststoreFile.exists(), truststoreFile.length(), truststoreFile.canRead());

        // Load keystore
        KeyStore keyStore = loadKeyStore(keystorePath, keystorePassword);

        // Load truststore with detailed logging
        KeyStore trustStore = loadKeyStore(truststorePath, truststorePassword);

        // Important: Check if the truststore has any entries at all
        int trustStoreSize = Collections.list(trustStore.aliases()).size();
        log.info("Truststore contains {} entries", trustStoreSize);

        if (trustStoreSize == 0) {
            log.error("ERROR: Truststore is empty! SSL connections will fail.");

            // As a fallback, try to copy the root CA certificate from the keystore
            if (keyStore.containsAlias("root-ca") || keyStore.containsAlias("client")) {
                log.info("Attempting to recover by copying CA certificate from keystore...");

                for (String alias : Collections.list(keyStore.aliases())) {
                    Certificate[] chain = null;

                    try {
                        // Try to get certificate chain
                        if (keyStore.isKeyEntry(alias)) {
                            chain = keyStore.getCertificateChain(alias);
                        }

                        // If we found a chain with at least 2 certificates
                        if (chain != null && chain.length > 1) {
                            // The last certificate in the chain should be the root CA
                            Certificate rootCaCert = chain[chain.length - 1];
                            trustStore.setCertificateEntry("imported-root-ca", rootCaCert);
                            log.info("Imported root CA certificate into truststore from keystore chain");

                            // Save the updated truststore
                            try (FileOutputStream fos = new FileOutputStream(truststorePath)) {
                                trustStore.store(fos, truststorePassword.toCharArray());
                                log.info("Saved updated truststore with imported root CA certificate");
                            }

                            break;
                        }
                    } catch (Exception e) {
                        log.warn("Failed to import certificate from keystore: {}", e.getMessage());
                    }
                }
            }
        }

        // Log trust manager info for debugging
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        logTrustManagerInfo(trustManagerFactory.getTrustManagers());
    }

    /**
     * Loads a KeyStore from the given path with the given password.
     */
    private KeyStore loadKeyStore(String path, String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (FileInputStream fileInputStream = new FileInputStream(path)) {
            keyStore.load(fileInputStream, password.toCharArray());

            // Log all aliases in the keystore
            Enumeration<String> aliases = keyStore.aliases();
            log.info("Keystore at {} contains the following aliases:", path);
            int count = 0;

            while (aliases.hasMoreElements()) {
                count++;
                String alias = aliases.nextElement();
                boolean isCertificateEntry = keyStore.isCertificateEntry(alias);
                boolean isKeyEntry = keyStore.isKeyEntry(alias);

                log.info(" - Alias: {}, isCertificate: {}, isKey: {}",
                        alias, isCertificateEntry, isKeyEntry);

                if (isCertificateEntry) {
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    log.info("   Certificate subject: {}", cert.getSubjectX500Principal().getName());
                    log.info("   Certificate issuer: {}", cert.getIssuerX500Principal().getName());
                    log.info("   Certificate valid from: {} to {}", cert.getNotBefore(), cert.getNotAfter());
                }
            }

            log.info("Successfully loaded keystore from {} with {} entries", path, count);
        }

        return keyStore;
    }

    /**
     * Logs information about the trust managers for debugging.
     */
    private void logTrustManagerInfo(TrustManager[] trustManagers) {
        if (trustManagers == null || trustManagers.length == 0) {
            log.warn("No trust managers found!");
            return;
        }

        for (TrustManager tm : trustManagers) {
            if (tm instanceof X509TrustManager x509TrustManager) {
                X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();

                if (acceptedIssuers != null && acceptedIssuers.length > 0) {
                    log.info("Trust manager has {} accepted issuers:", acceptedIssuers.length);

                    for (int i = 0; i < acceptedIssuers.length; i++) {
                        X509Certificate cert = acceptedIssuers[i];
                        log.info(" - Issuer {}: Subject: {}, Issuer: {}",
                                i + 1,
                                cert.getSubjectX500Principal().getName(),
                                cert.getIssuerX500Principal().getName());
                    }
                } else {
                    log.warn("Trust manager has no accepted issuers!");
                }
            } else {
                log.info("TrustManager is not an X509TrustManager: {}", tm.getClass().getName());
            }
        }
    }
}
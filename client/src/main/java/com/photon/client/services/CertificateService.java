//package com.photon.client.services;
//
//import lombok.extern.slf4j.Slf4j;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Service;
//
//import jakarta.annotation.PostConstruct;
//import java.io.FileInputStream;
//import java.io.IOException;
//import java.security.*;
//import java.security.cert.Certificate;
//import java.security.cert.CertificateException;
//import java.security.cert.X509Certificate;
//
///**
// * This service loads pre-generated certificates instead of downloading them from the server.
// */
//@Service
//@Slf4j
//public class CertificateService {
//
//    static {
//        Security.addProvider(new BouncyCastleProvider());
//        System.setProperty("keystore.pkcs12.keyProtectionAlgorithm", "PBEWithHmacSHA256AndAES_256");
//        System.setProperty("keystore.pkcs12.certProtectionAlgorithm", "PBEWithHmacSHA256AndAES_256");
//    }
//
//    @Value("${client.ssl.key-store}")
//    private String clientKeystorePath;
//
//    @Value("${client.ssl.key-store-password}")
//    private String clientKeystorePassword;
//
//    @Value("${client.ssl.trust-store}")
//    private String truststorePath;
//
//    @Value("${client.ssl.trust-store-password}")
//    private String truststorePassword;
//
//    @PostConstruct
//    public void init() {
//        try {
//            // Load and verify the certificates
//            verifyClientCertificate();
//            verifyTruststore();
//            log.info("Certificates loaded and verified successfully");
//        } catch (Exception e) {
//            log.error("Error loading certificates", e);
//        }
//    }
//
//    private void verifyClientCertificate() throws Exception {
//        try {
//            // Load the client keystore
//            KeyStore clientKeystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
//            try (FileInputStream fis = new FileInputStream(clientKeystorePath)) {
//                clientKeystore.load(fis, clientKeystorePassword.toCharArray());
//            }
//
//            // Check if the client certificate and private key exist
//            if (!clientKeystore.isKeyEntry("client")) {
//                throw new Exception("Client key entry not found in keystore");
//            }
//
//            // Get client certificate
//            Certificate cert = clientKeystore.getCertificate("client");
//            if (!(cert instanceof X509Certificate clientCert)) {
//                throw new Exception("Client certificate is not an X509Certificate");
//            }
//
//            log.info("Client certificate loaded successfully: {}",
//                    clientCert.getSubjectX500Principal().getName());
//
//            // Verify private key is available
//            Key key = clientKeystore.getKey("client", clientKeystorePassword.toCharArray());
//            if (!(key instanceof PrivateKey)) {
//                throw new Exception("Client private key not found");
//            }
//
//            log.info("Client private key verified successfully");
//        } catch (IOException | KeyStoreException | NoSuchAlgorithmException |
//                 CertificateException | UnrecoverableKeyException | NoSuchProviderException e) {
//            log.error("Failed to load client certificate", e);
//            throw new Exception("Client certificate verification failed", e);
//        }
//    }
//
//    private void verifyTruststore() throws Exception {
//        try {
//            // Load the truststore
//            KeyStore truststore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
//            try (FileInputStream fis = new FileInputStream(truststorePath)) {
//                truststore.load(fis, truststorePassword.toCharArray());
//            }
//
//            // Check if the root CA certificate exists
//            if (!truststore.isCertificateEntry("root-ca")) {
//                throw new Exception("Root CA certificate not found in truststore");
//            }
//
//            // Get root CA certificate
//            Certificate cert = truststore.getCertificate("root-ca");
//            if (!(cert instanceof X509Certificate rootCACert)) {
//                throw new Exception("Root CA certificate is not an X509Certificate");
//            }
//
//            log.info("Root CA certificate loaded from truststore: {}",
//                    rootCACert.getSubjectX500Principal().getName());
//
//        } catch (IOException | KeyStoreException | NoSuchAlgorithmException |
//                 CertificateException | NoSuchProviderException e) {
//            log.error("Failed to load truststore", e);
//            throw new Exception("Truststore verification failed", e);
//        }
//    }
//}
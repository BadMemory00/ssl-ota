//package com.photon.server.services;
//
//import lombok.Getter;
//import lombok.extern.slf4j.Slf4j;
//import org.bouncycastle.asn1.x500.X500Name;
//import org.bouncycastle.asn1.x509.BasicConstraints;
//import org.bouncycastle.asn1.x509.Extension;
//import org.bouncycastle.asn1.x509.KeyUsage;
//import org.bouncycastle.cert.X509CertificateHolder;
//import org.bouncycastle.cert.X509v3CertificateBuilder;
//import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
//import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.operator.ContentSigner;
//import org.bouncycastle.operator.OperatorCreationException;
//import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Service;
//
//import jakarta.annotation.PostConstruct;
//
//import java.io.File;
//import java.io.FileOutputStream;
//import java.io.IOException;
//import java.math.BigInteger;
//import java.security.*;
//import java.security.cert.Certificate;
//import java.security.cert.CertificateException;
//import java.security.cert.X509Certificate;
//import java.util.Date;
//
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
//    @Value("${server.ssl.key-store}")
//    private String serverKeystorePath;
//
//    @Value("${server.ssl.key-store-password}")
//    private String serverKeystorePassword;
//
//    @Value("${server.ssl.trust-store}")
//    private String truststorePath;
//
//    @Value("${server.ssl.trust-store-password}")
//    private String truststorePassword;
//
//    @Value("${cert.root-ca.path:certs/root-ca.p12}")
//    private String rootCAPath;
//
//    @Value("${cert.root-ca.password:changeit}")
//    private String rootCAPassword;
//
//    private static final String KEY_ALGORITHM = "RSA";
//    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
//    private static final int KEY_SIZE = 2048;
//    private static final long VALIDITY_PERIOD = 365L * 24L * 60L * 60L * 1000L; // 1 year in milliseconds
//
//    private KeyPair rootKeyPair;
//    @Getter
//    private X509Certificate rootCertificate;
//
//    @PostConstruct
//    public void init() {
//        try {
//            generateCertificates();
//        } catch (Exception e) {
//            log.error("Error generating certificates", e);
//        }
//    }
//
//    public void generateCertificates() {
//        try {
//            // Create directories if they don't exist
//            File serverKeystoreDir = new File(serverKeystorePath).getParentFile();
//            File truststoreDir = new File(truststorePath).getParentFile();
//            File rootCADir = new File(rootCAPath).getParentFile();
//
//            if (serverKeystoreDir != null && !serverKeystoreDir.exists()) {
//                serverKeystoreDir.mkdirs();
//            }
//
//            if (truststoreDir != null && !truststoreDir.exists()) {
//                truststoreDir.mkdirs();
//            }
//
//            if (rootCADir != null && !rootCADir.exists()) {
//                rootCADir.mkdirs();
//            }
//
//            // Generate Root CA certificate
//            generateRootCA();
//            log.info("Root CA certificate generated successfully");
//
//            // Generate Server certificate
//            generateServerCertificate();
//            log.info("Server certificate generated successfully");
//
//            // Export Root CA certificate to truststore
//            exportRootCertificate();
//            log.info("Root CA exported to truststore successfully");
//
//        } catch (Exception e) {
//            log.error("Error generating certificates", e);
//        }
//    }
//
//    private void generateRootCA()
//            throws NoSuchAlgorithmException, OperatorCreationException, CertificateException,
//            IOException, KeyStoreException, NoSuchProviderException {
//
//        // Generate key pair for Root CA
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
//        keyPairGenerator.initialize(KEY_SIZE);
//        rootKeyPair = keyPairGenerator.generateKeyPair();
//
//        // Set certificate validity period
//        long now = System.currentTimeMillis();
//        Date startDate = new Date(now);
//        Date endDate = new Date(now + VALIDITY_PERIOD);
//
//        // Create X500 name for the Root CA
//        X500Name rootCertIssuer = new X500Name("CN=Root CA, O=Example, C=US");
//        BigInteger rootSerialNum = new BigInteger(Long.toString(now));
//
//        // Certificate builder for Root CA
//        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(
//                rootCertIssuer, rootSerialNum, startDate, endDate, rootCertIssuer, rootKeyPair.getPublic());
//
//        // Add extensions to the Root CA certificate
//        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
//
//        // Set key usage for CA certificate
//        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
//        rootCertBuilder.addExtension(Extension.keyUsage, true, keyUsage);
//
//        // Create content signer for the Root CA certificate
//        ContentSigner rootCertSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
//                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
//                .build(rootKeyPair.getPrivate());
//
//        // Generate the Root CA certificate
//        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertSigner);
//        rootCertificate = new JcaX509CertificateConverter()
//                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
//                .getCertificate(rootCertHolder);
//
//        // Store Root CA in its own keystore
//        KeyStore rootCAKeystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
//        rootCAKeystore.load(null, null);
//        rootCAKeystore.setKeyEntry("root-ca", rootKeyPair.getPrivate(),
//                rootCAPassword.toCharArray(), new Certificate[]{rootCertificate});
//
//        try (FileOutputStream fos = new FileOutputStream(rootCAPath)) {
//            rootCAKeystore.store(fos, rootCAPassword.toCharArray());
//        }
//    }
//
//    private void generateServerCertificate()
//            throws NoSuchAlgorithmException, OperatorCreationException, CertificateException,
//            IOException, KeyStoreException, NoSuchProviderException {
//
//        // Generate key pair for the server certificate
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
//        keyPairGenerator.initialize(KEY_SIZE);
//        KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();
//
//        // Set certificate validity period
//        long now = System.currentTimeMillis();
//        Date startDate = new Date(now);
//        Date endDate = new Date(now + VALIDITY_PERIOD);
//
//        // Create X500 name for the certificate
//        X500Name issuer = new X500Name("CN=Root CA, O=Example, C=US");
//        X500Name subject = new X500Name("CN=Server, O=Example, C=US");
//        BigInteger serialNum = new BigInteger(Long.toString(now + 1)); // Ensure unique serial number
//
//        // Certificate builder
//        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
//                issuer, serialNum, startDate, endDate, subject, serverKeyPair.getPublic());
//
//        // Add extensions to the certificate
//        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
//
//        // Set key usage for end-entity certificate
//        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
//        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
//
//        // Create content signer using the Root CA private key
//        ContentSigner certSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
//                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
//                .build(rootKeyPair.getPrivate());
//
//        // Generate the certificate
//        X509CertificateHolder certHolder = certBuilder.build(certSigner);
//        X509Certificate serverCertificate = new JcaX509CertificateConverter()
//                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
//                .getCertificate(certHolder);
//
//        // Create a certificate chain
//        Certificate[] chain = new Certificate[]{serverCertificate, rootCertificate};
//
//        // Store the server certificate and private key in a keystore
//        KeyStore serverKeystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
//        serverKeystore.load(null, null); // Initialize an empty keystore
//        serverKeystore.setKeyEntry("server", serverKeyPair.getPrivate(),
//                serverKeystorePassword.toCharArray(), chain);
//
//        // Save the keystore to a file
//        try (FileOutputStream fos = new FileOutputStream(serverKeystorePath)) {
//            serverKeystore.store(fos, serverKeystorePassword.toCharArray());
//        }
//    }
//
//    private void exportRootCertificate()
//            throws KeyStoreException, IOException, NoSuchAlgorithmException,
//            CertificateException, NoSuchProviderException {
//
//        // Create a new keystore for the truststore
//        KeyStore trustStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
//        trustStore.load(null, null); // Initialize an empty keystore
//
//        // Add the Root CA certificate to the truststore
//        trustStore.setCertificateEntry("root-ca", rootCertificate);
//
//        // Save the truststore to a file
//        try (FileOutputStream fos = new FileOutputStream(truststorePath)) {
//            trustStore.store(fos, truststorePassword.toCharArray());
//        }
//    }
//
//    public KeyPair getRootKeyPair() {
//        return rootKeyPair;
//    }
//}
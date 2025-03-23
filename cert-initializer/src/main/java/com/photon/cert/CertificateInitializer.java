package com.photon.cert;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

@SpringBootApplication
@Slf4j
public class CertificateInitializer implements ApplicationRunner {

    static {
        Security.addProvider(new BouncyCastleProvider());
        System.setProperty("keystore.pkcs12.keyProtectionAlgorithm", "PBEWithHmacSHA256AndAES_256");
        System.setProperty("keystore.pkcs12.certProtectionAlgorithm", "PBEWithHmacSHA256AndAES_256");
    }

    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE = 2048;
    private static final long VALIDITY_PERIOD = 365L * 24L * 60L * 60L * 1000L; // 1 year in milliseconds

    private KeyPair rootKeyPair;
    private X509Certificate rootCertificate;

    public static void main(String[] args) {
        SpringApplication.run(CertificateInitializer.class, args);
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("Starting certificate initialization...");

        String certsDir = System.getenv().getOrDefault("CERTS_DIR", "certs");

        // Create certificates directory if it doesn't exist
        new File(certsDir).mkdirs();

        String rootCAPath = certsDir + "/root-ca.p12";
        String serverKeystorePath = certsDir + "/server.p12";
        String clientKeystorePath = certsDir + "/client.p12";
        String truststorePath = certsDir + "/truststore.p12";

        String keystorePassword = System.getenv().getOrDefault("KEYSTORE_PASSWORD", "changeit");

        try {
            // Generate Root CA
            generateRootCA(rootCAPath, keystorePassword);
            log.info("Root CA generated successfully at {}", rootCAPath);

            // Generate Server certificate
            generateCertificate(serverKeystorePath, keystorePassword, "server", "CN=Server, O=Example, C=US");
            log.info("Server certificate generated successfully at {}", serverKeystorePath);

            // Generate Client certificate
            generateCertificate(clientKeystorePath, keystorePassword, "client", "CN=Client, O=Example, C=US");
            log.info("Client certificate generated successfully at {}", clientKeystorePath);

            // Create truststore with Root CA certificate
            exportRootCertificateToTruststore(truststorePath, keystorePassword);
            log.info("Truststore with Root CA generated successfully at {}", truststorePath);

            log.info("Certificate initialization completed successfully!");

            // Exit after certificate generation is complete
            System.exit(0);
        } catch (Exception e) {
            log.error("Error generating certificates", e);
            System.exit(1);
        }
    }

    private void generateRootCA(String keystorePath, String keystorePassword) throws Exception {
        // Generate key pair for Root CA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        rootKeyPair = keyPairGenerator.generateKeyPair();

        // Set certificate validity period
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + VALIDITY_PERIOD);

        // Create X500 name for the Root CA
        X500Name rootCertIssuer = new X500Name("CN=Root CA, O=Example, C=US");
        X500Name rootCertSubject = rootCertIssuer;
        BigInteger rootSerialNum = new BigInteger(Long.toString(now));

        // Certificate builder for Root CA
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(
                rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        // Add extensions to the Root CA certificate
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        // Set key usage for CA certificate
        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        rootCertBuilder.addExtension(Extension.keyUsage, true, keyUsage);

        // Create content signer for the Root CA certificate
        ContentSigner rootCertSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(rootKeyPair.getPrivate());

        // Generate the Root CA certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertSigner);
        rootCertificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(rootCertHolder);

        // Store the Root CA in a keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry("root-ca", rootKeyPair.getPrivate(), keystorePassword.toCharArray(),
                new Certificate[]{rootCertificate});

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, keystorePassword.toCharArray());
        }
    }

    private void generateCertificate(String keystorePath, String password, String alias, String subjectDN)
            throws Exception {
        // Generate key pair for the certificate
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Set certificate validity period
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + VALIDITY_PERIOD);

        // Create X500 name for the certificate
        X500Name issuer = new X500Name("CN=Root CA, O=Example, C=US");
        X500Name subject = new X500Name(subjectDN);
        BigInteger serialNum = new BigInteger(Long.toString(now + System.nanoTime())); // Ensure unique serial number

        // Certificate builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNum, startDate, endDate, subject, keyPair.getPublic());

        // Add extensions to the certificate
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Set key usage for end-entity certificate
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

        // Create content signer using the Root CA private key
        ContentSigner certSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(rootKeyPair.getPrivate());

        // Generate the certificate
        X509CertificateHolder certHolder = certBuilder.build(certSigner);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certHolder);

        // Create a certificate chain
        Certificate[] chain = new Certificate[]{certificate, rootCertificate};

        // Store the certificate and private key in a keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), chain);

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    private void exportRootCertificateToTruststore(String truststorePath, String truststorePassword) throws Exception {
        // Create a truststore with the Root CA certificate
        KeyStore trustStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        trustStore.load(null, null);
        trustStore.setCertificateEntry("root-ca", rootCertificate);

        try (FileOutputStream fos = new FileOutputStream(truststorePath)) {
            trustStore.store(fos, truststorePassword.toCharArray());
        }
    }
}
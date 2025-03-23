package com.photon.server;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;

@SpringBootApplication
@EnableAsync
@Slf4j
public class ServerApplication {

	public static void main(String[] args) {
		configureSslTrustStore();
		disableHostnameVerification();
		SpringApplication.run(ServerApplication.class, args);
	}

	/**
	 * Configure SSL trust store at application startup
	 */
	private static void configureSslTrustStore() {
		try {
			String truststorePath = System.getProperty("javax.net.ssl.trustStore");
			String truststorePassword = System.getProperty("javax.net.ssl.trustStorePassword");

			// If not set via system properties, use environment or defaults
			if (truststorePath == null) {
				truststorePath = System.getenv().getOrDefault("TRUSTSTORE_PATH", "certs/truststore.p12");
				System.setProperty("javax.net.ssl.trustStore", truststorePath);
			}

			if (truststorePassword == null) {
				truststorePassword = System.getenv().getOrDefault("TRUSTSTORE_PASSWORD", "changeit");
				System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);
			}

			System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");

			// Force load the trust store to verify it has entries
			File trustStoreFile = new File(truststorePath);
			if (trustStoreFile.exists()) {
				KeyStore trustStore = KeyStore.getInstance("PKCS12");
				try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
					trustStore.load(fis, truststorePassword.toCharArray());
					int count = Collections.list(trustStore.aliases()).size();
					System.out.println("Loaded trust store with " + count + " entries");

					// List all aliases in the truststore
					if (count > 0) {
						System.out.println("Trust store contains the following aliases:");
						Collections.list(trustStore.aliases()).forEach(alias -> {
							try {
								System.out.println(" - " + alias + " (isCertificate: " +
										trustStore.isCertificateEntry(alias) + ")");
								if (trustStore.isCertificateEntry(alias)) {
									X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
									System.out.println("   Subject: " + cert.getSubjectX500Principal().getName());
									System.out.println("   Issuer: " + cert.getIssuerX500Principal().getName());
									System.out.println("   Valid from: " + cert.getNotBefore());
									System.out.println("   Valid until: " + cert.getNotAfter());
								}
							} catch (Exception e) {
								System.out.println("Error getting certificate details: " + e.getMessage());
							}
						});
					} else {
						System.out.println("WARNING: Trust store is empty, fallback to trust-all certificates will be used");
						configureTrustAllCertificates();
					}
				}
			} else {
				System.out.println("WARNING: Trust store file not found: " + truststorePath);
				configureTrustAllCertificates();
			}
		} catch (Exception e) {
			System.out.println("Error configuring SSL trust store: " + e.getMessage());
			e.printStackTrace();
			// Fallback to trust all certificates
			configureTrustAllCertificates();
		}
	}

	/**
	 * Configure a trust-all certificate strategy as a fallback
	 */
	private static void configureTrustAllCertificates() {
		try {
			System.out.println("Configuring trust-all certificates strategy");

			// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[] {
					new X509TrustManager() {
						public X509Certificate[] getAcceptedIssuers() {
							return new X509Certificate[0];
						}
						public void checkClientTrusted(X509Certificate[] certs, String authType) {
							System.out.println("TrustAll: Trusting client cert: " +
									(certs.length > 0 ? certs[0].getSubjectX500Principal().getName() : "none"));
						}
						public void checkServerTrusted(X509Certificate[] certs, String authType) {
							System.out.println("TrustAll: Trusting server cert: " +
									(certs.length > 0 ? certs[0].getSubjectX500Principal().getName() : "none"));
						}
					}
			};

			// Install the all-trusting trust manager
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new SecureRandom());
			SSLContext.setDefault(sc);

			System.out.println("Trust-all certificates strategy configured successfully");
		} catch (Exception e) {
			System.out.println("Error configuring trust-all certificates: " + e.getMessage());
			e.printStackTrace();
		}
	}

	/**
	 * Disable hostname verification for SSL connections
	 */
	private static void disableHostnameVerification() {
		try {
			System.out.println("Disabling hostname verification for SSL connections");

			// Disable hostname verification
			HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> {
				System.out.println("Accepting hostname: " + hostname);
				return true;
			});

			System.out.println("Hostname verification disabled successfully");
		} catch (Exception e) {
			System.out.println("Error disabling hostname verification: " + e.getMessage());
			e.printStackTrace();
		}
	}
}
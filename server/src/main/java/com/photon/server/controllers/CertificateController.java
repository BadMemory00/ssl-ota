package com.photon.server.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller to expose the Root CA certificate and keystores so that the client can download them
 */
@RestController
@RequestMapping("/api/certificates")
@Slf4j
class CertificateController {

    @Value("${cert.root-ca.path:certs/root-ca.p12}")
    private String rootCAPath;

    @Value("${server.ssl.trust-store}")
    private String truststorePath;

    @GetMapping("/root-ca")
    public Resource downloadRootCA() {
        log.info("Downloading Root CA from: {}", rootCAPath);
        return new FileSystemResource(rootCAPath);
    }

    @GetMapping("/truststore")
    public Resource downloadTruststore() {
        log.info("Downloading truststore from: {}", truststorePath);
        return new FileSystemResource(truststorePath);
    }
}
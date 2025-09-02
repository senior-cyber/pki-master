package com.senior.cyber.pki.common.x509;

import lombok.Getter;

import java.security.cert.X509Certificate;

public class CrossSignRoot {

    @Getter
    private final X509Certificate rootCertificate;

    @Getter
    private final X509Certificate crossRootCertificate;

    public CrossSignRoot(X509Certificate rootCertificate, X509Certificate crossRootCertificate) {
        this.rootCertificate = rootCertificate;
        this.crossRootCertificate = crossRootCertificate;
    }

}

package com.senior.cyber.pki.service.util;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class Crypto {

    private Provider provider;

    private X509Certificate certificate;

    private PublicKey publicKey;

    private PrivateKey privateKey;

    public Crypto(Provider provider, X509Certificate certificate, PrivateKey privateKey) {
        this.provider = provider;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public Crypto(Provider provider, PublicKey publicKey, PrivateKey privateKey) {
        this.provider = provider;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public Provider getProvider() {
        return provider;
    }

    public void setProvider(Provider provider) {
        this.provider = provider;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

@Setter
@Getter
public class RootGenerateResponse implements Serializable {

    @JsonProperty("id")
    private String id;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("certificate")
    private X509Certificate certificate;

    @JsonProperty("certificateBase64")
    private String certificateBase64;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("privateKey")
    private PrivateKey privateKey;

    @JsonProperty("privateKeyBase64")
    private String privateKeyBase64;

    @JsonProperty("sshCa")
    private String sshCa;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("ocspCertificate")
    private X509Certificate ocspCertificate;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("ocspPublicKey")
    private PublicKey ocspPublicKey;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("ocspPrivateKey")
    private PrivateKey ocspPrivateKey;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("crlCertificate")
    private X509Certificate crlCertificate;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("crlPublicKey")
    private PublicKey crlPublicKey;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("crlPrivateKey")
    private PrivateKey crlPrivateKey;

}

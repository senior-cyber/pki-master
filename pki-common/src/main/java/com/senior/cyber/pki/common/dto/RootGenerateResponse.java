package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PKCS10CertificationRequestDeserializer;
import com.senior.cyber.pki.common.converter.PKCS10CertificationRequestSerializer;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

@Setter
@Getter
public class RootGenerateResponse implements Serializable {

    @JsonProperty("keyId")
    private String keyId;

    @JsonSerialize(using = PKCS10CertificationRequestSerializer.class)
    @JsonDeserialize(using = PKCS10CertificationRequestDeserializer.class)
    @JsonProperty("certificate")
    private X509Certificate certificate;

    @JsonSerialize(using = PKCS10CertificationRequestSerializer.class)
    @JsonDeserialize(using = PKCS10CertificationRequestDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonSerialize(using = PKCS10CertificationRequestSerializer.class)
    @JsonDeserialize(using = PKCS10CertificationRequestDeserializer.class)
    @JsonProperty("privateKey")
    private PrivateKey privateKey;

}

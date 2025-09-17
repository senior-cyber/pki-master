package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

@Setter
@Getter
@Builder
public class KeyInfoResponse extends BaseResponse {

    @JsonProperty("type")
    private KeyTypeEnum type;

    @JsonProperty("format")
    private KeyFormatEnum format;

    @JsonProperty("size")
    private Integer size;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("privateKey")
    private PrivateKey privateKey;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("certificate")
    private X509Certificate certificate;

    @JsonProperty("decentralized")
    private boolean decentralized;

    @JsonCreator
    public static KeyInfoResponse create() {
        return KeyInfoResponse.builder().build();
    }

}

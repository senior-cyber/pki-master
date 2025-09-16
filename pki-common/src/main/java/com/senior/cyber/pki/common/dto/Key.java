package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.PublicKeySerializer;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;

import java.io.Serializable;
import java.security.PublicKey;

@Getter
@Setter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class Key implements Serializable {

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonProperty("privateKey")
    private String privateKey;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonProperty("type")
    private KeyTypeEnum type;

    @JsonProperty("format")
    private KeyFormatEnum format;

    @JsonProperty("size")
    private int size;

    @JsonProperty("decentralized")
    private boolean decentralized;

}

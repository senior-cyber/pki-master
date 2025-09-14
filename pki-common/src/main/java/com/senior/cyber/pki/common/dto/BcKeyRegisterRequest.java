package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.PublicKeySerializer;
import com.senior.cyber.pki.common.x509.KeyFormat;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PublicKey;

@Setter
@Getter
public class BcKeyRegisterRequest implements Serializable {

    @JsonProperty("size")
    private int size;

    @JsonProperty("format")
    private KeyFormat format;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    public BcKeyRegisterRequest() {
    }

    public BcKeyRegisterRequest(int size, KeyFormat format, PublicKey publicKey) {
        this.size = size;
        this.format = format;
        this.publicKey = publicKey;
    }

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PrivateKeyDeserializer;
import com.senior.cyber.pki.common.converter.PrivateKeySerializer;
import com.senior.cyber.pki.common.converter.PublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.PublicKeySerializer;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

@Setter
@Getter
public class JcaKeyRegisterRequest implements Serializable {

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("privateKey")
    private PrivateKey privateKey;

}

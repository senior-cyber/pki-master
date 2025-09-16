package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.OpenSshPublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.OpenSshPublicKeySerializer;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.security.PublicKey;

@Getter
@Setter
@Builder
public class KeyGenerateResponse1 extends BaseResponse {

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonProperty("openSshPublicKey")
    @JsonSerialize(using = OpenSshPublicKeySerializer.class)
    @JsonDeserialize(using = OpenSshPublicKeyDeserializer.class)
    private PublicKey openSshPublicKey;

    @JsonCreator
    public static KeyGenerateResponse1 create() {
        return KeyGenerateResponse1.builder().build();
    }

}
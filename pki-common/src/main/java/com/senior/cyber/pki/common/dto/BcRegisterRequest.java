package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.PublicKeySerializer;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.security.PublicKey;

@Setter
@Getter
@Builder
public class BcRegisterRequest extends BaseRequest {

    @JsonProperty("size")
    private int size;

    @JsonProperty("format")
    private KeyFormatEnum format;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonProperty("emailAddress")
    private String emailAddress;

    @JsonCreator
    public static BcRegisterRequest create() {
        return BcRegisterRequest.builder().build();
    }

}

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

@Setter
@Getter
@Builder
public class SshGenerateResponse extends BaseResponse {

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonProperty("sshCa")
    @JsonSerialize(using = OpenSshPublicKeySerializer.class)
    @JsonDeserialize(using = OpenSshPublicKeyDeserializer.class)
    private PublicKey sshCa;

    @JsonCreator
    public static SshGenerateResponse create() {
        return SshGenerateResponse.builder().build();
    }

}

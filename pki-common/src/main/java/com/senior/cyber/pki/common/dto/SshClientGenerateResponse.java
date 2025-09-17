package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.apache.sshd.common.config.keys.OpenSshCertificate;

import java.security.PrivateKey;
import java.security.PublicKey;

@Setter
@Getter
@Builder
public class SshClientGenerateResponse extends BaseResponse {

    @JsonProperty("openSshCertificate")
    @JsonSerialize(using = OpenSshCertificateSerializer.class)
    @JsonDeserialize(using = OpenSshCertificateDeserializer.class)
    private OpenSshCertificate openSshCertificate;

    @JsonProperty("openSshPublicKey")
    @JsonSerialize(using = OpenSshPublicKeySerializer.class)
    @JsonDeserialize(using = OpenSshPublicKeyDeserializer.class)
    private PublicKey openSshPublicKey;

    @JsonSerialize(using = OpenSshPrivateKeySerializer.class)
    @JsonDeserialize(using = OpenSshPrivateKeyDeserializer.class)
    @JsonProperty("openSshPrivateKey")
    private PrivateKey openSshPrivateKey;

    @JsonProperty("config")
    private String config;

    @JsonCreator
    public static SshClientGenerateResponse create() {
        return SshClientGenerateResponse.builder().build();
    }

}

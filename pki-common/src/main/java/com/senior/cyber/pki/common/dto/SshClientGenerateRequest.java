package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.OpenSshPublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.OpenSshPublicKeySerializer;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PublicKey;

@Setter
@Getter
public class SshClientGenerateRequest implements Serializable {

    @JsonProperty("issuer")
    private Issuer issuer;

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonProperty("principal")
    private String principal;

    @JsonProperty("server")
    private String server;

    @JsonProperty("validityPeriod")
    private long validityPeriod;

}

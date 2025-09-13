package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

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

    @JsonProperty("alias")
    private String alias;

    @JsonProperty("validityPeriod")
    private long validityPeriod;

}

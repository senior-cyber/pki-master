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

    /**
     * PnYnMnDTnHnMnS
     */
    @JsonProperty("period")
    private String period;

    public SshClientGenerateRequest() {
    }

    public SshClientGenerateRequest(Issuer issuer, String keyId, String keyPassword, String principal, String server, String alias, String period) {
        this.issuer = issuer;
        this.keyId = keyId;
        this.keyPassword = keyPassword;
        this.principal = principal;
        this.server = server;
        this.alias = alias;
        this.period = period;
    }

}

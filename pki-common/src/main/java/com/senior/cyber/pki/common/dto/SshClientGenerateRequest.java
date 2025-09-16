package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;

import java.io.Serializable;

@Setter
@Getter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
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

}

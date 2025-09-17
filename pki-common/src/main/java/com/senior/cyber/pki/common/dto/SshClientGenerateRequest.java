package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class SshClientGenerateRequest extends BaseRequest {

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

    @JsonCreator
    public static SshClientGenerateRequest create() {
        return SshClientGenerateRequest.builder().build();
    }

}

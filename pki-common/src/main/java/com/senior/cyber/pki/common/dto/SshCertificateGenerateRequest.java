package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class SshCertificateGenerateRequest implements Serializable {

    @JsonProperty("issuerKeyId")
    private String issuerKeyId;

    @JsonProperty("issuerKeyPassword")
    private String issuerKeyPassword;

    @JsonProperty("opensshPublicKey")
    private String opensshPublicKey;

    @JsonProperty("principal")
    private String principal;

    @JsonProperty("server")
    private String server;

    @JsonProperty("validityPeriod")
    private long validityPeriod;

}

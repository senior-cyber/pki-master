package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PrivateKeyDeserializer;
import com.senior.cyber.pki.common.converter.PrivateKeySerializer;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PrivateKey;

@Setter
@Getter
public class SshCertificateGenerateRequest implements Serializable {

    @JsonProperty("issuerKeyId")
    private String issuerKeyId;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("issuerPrivateKey")
    private PrivateKey issuerPrivateKey;

    @JsonProperty("opensshPublicKey")
    private String opensshPublicKey;

    @JsonProperty("principal")
    private String principal;

    @JsonProperty("server")
    private String server;

    @JsonProperty("validityPeriod")
    private long validityPeriod;

}

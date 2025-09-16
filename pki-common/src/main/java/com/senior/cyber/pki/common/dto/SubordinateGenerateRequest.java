package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;

import java.io.Serializable;

@Getter
@Setter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class SubordinateGenerateRequest implements Serializable {

    @JsonProperty("issuer")
    private Issuer issuer;

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonProperty("subject")
    private Subject subject;

}

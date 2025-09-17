package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class Issuer implements Serializable {

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonCreator
    public static Issuer create() {
        return Issuer.builder().build();
    }

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class Issuer {

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonProperty("keyId")
    private String keyId;

    public Issuer(String certificateId, String keyId, String keyPassword) {
        this.certificateId = certificateId;
        this.keyPassword = keyPassword;
        this.keyId = keyId;
    }

    public Issuer() {
    }

}

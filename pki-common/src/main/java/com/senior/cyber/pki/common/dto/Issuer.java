package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class Issuer {

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    public Issuer() {
    }

    public Issuer(String certificateId, String keyId, String keyPassword) {
        this.certificateId = certificateId;
        this.keyPassword = keyPassword;
        this.keyId = keyId;
    }

}

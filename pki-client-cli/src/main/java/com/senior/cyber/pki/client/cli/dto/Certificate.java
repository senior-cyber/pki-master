package com.senior.cyber.pki.client.cli.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class Certificate {

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    public Certificate() {
    }

    public Certificate(String certificateId, String keyPassword) {
        this.certificateId = certificateId;
        this.keyPassword = keyPassword;
    }

}

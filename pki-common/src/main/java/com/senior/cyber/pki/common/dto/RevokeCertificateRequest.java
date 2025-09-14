package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class RevokeCertificateRequest implements Serializable {

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    public RevokeCertificateRequest() {
    }

    public RevokeCertificateRequest(String certificateId, String keyPassword) {
        this.certificateId = certificateId;
        this.keyPassword = keyPassword;
    }

}

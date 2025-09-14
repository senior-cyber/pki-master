package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class RevokeKeyRequest implements Serializable {

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    public RevokeKeyRequest() {
    }

    public RevokeKeyRequest(String keyId, String keyPassword) {
        this.keyId = keyId;
        this.keyPassword = keyPassword;
    }

}

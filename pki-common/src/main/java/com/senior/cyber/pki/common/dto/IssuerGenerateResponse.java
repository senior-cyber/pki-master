package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class IssuerGenerateResponse implements Serializable {

    @JsonProperty("serial")
    private long serial;

    @JsonProperty("keyId")
    private String keyId;

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.senior.cyber.pki.common.x509.KeyFormat;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class BcKeyGenerateRequest implements Serializable {

    @JsonProperty("size")
    private int size;

    @JsonProperty("format")
    private KeyFormat format;

    public BcKeyGenerateRequest() {
    }

    public BcKeyGenerateRequest(int size, KeyFormat format) {
        this.size = size;
        this.format = format;
    }

}

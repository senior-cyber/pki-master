package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class KeyBcGenerateRequest implements Serializable {

    @JsonProperty("size")
    private int size;

    @JsonProperty("format")
    private KeyFormatEnum format;

    public KeyBcGenerateRequest() {
    }

    public KeyBcGenerateRequest(int size, KeyFormatEnum format) {
        this.size = size;
        this.format = format;
    }

}

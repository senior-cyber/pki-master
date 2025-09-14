package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.senior.cyber.pki.common.x509.KeyFormat;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class YubicoKeyGenerateRequest implements Serializable {

    @JsonProperty("size")
    private int size;

    @JsonProperty("format")
    private KeyFormat format;

    @JsonProperty("serialNumber")
    private String serialNumber;

    @JsonProperty("slot")
    private String slot;

    @JsonProperty("managementKey")
    private String managementKey;

    public YubicoKeyGenerateRequest() {
    }

    public YubicoKeyGenerateRequest(int size, KeyFormat format, String serialNumber, String slot, String managementKey) {
        this.size = size;
        this.format = format;
        this.serialNumber = serialNumber;
        this.slot = slot;
        this.managementKey = managementKey;
    }

}

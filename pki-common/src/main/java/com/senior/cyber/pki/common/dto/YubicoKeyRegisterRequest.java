package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class YubicoKeyRegisterRequest implements Serializable {

    @JsonProperty("slot")
    private String slot;

    @JsonProperty("serialNumber")
    private String serialNumber;

    @JsonProperty("managementKey")
    private String managementKey;

    @JsonProperty("pin")
    private String pin;

    public YubicoKeyRegisterRequest() {
    }

    public YubicoKeyRegisterRequest(String slot, String serialNumber, String managementKey, String pin) {
        this.slot = slot;
        this.serialNumber = serialNumber;
        this.managementKey = managementKey;
        this.pin = pin;
    }

}

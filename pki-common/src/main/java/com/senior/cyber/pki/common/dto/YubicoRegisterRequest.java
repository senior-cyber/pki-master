package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.PublicKeySerializer;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PublicKey;

@Setter
@Getter
public class YubicoRegisterRequest implements Serializable {

    @JsonProperty("size")
    private int size;

    @JsonProperty("slot")
    private String slot;

    @JsonProperty("serialNumber")
    private String serialNumber;

    @JsonProperty("managementKey")
    private String managementKey;

    @JsonProperty("pin")
    private String pin;

    @JsonProperty("format")
    private KeyFormatEnum format;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    public YubicoRegisterRequest() {
    }

    public YubicoRegisterRequest(int size, String slot, String serialNumber, String managementKey, String pin) {
        this.size = size;
        this.slot = slot;
        this.serialNumber = serialNumber;
        this.managementKey = managementKey;
        this.pin = pin;
    }

}

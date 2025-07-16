package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class YubicoIssuerGenerateRequest implements Serializable {

    @JsonProperty("issuerId")
    private String issuerId;

    @JsonProperty("issuerSerialNumber")
    private String issuerSerialNumber;

    @JsonProperty("issuerManagementKey")
    private String issuerManagementKey;

    @JsonProperty("issuerSlot")
    private String issuerSlot;

    @JsonProperty("issuerPin")
    private String issuerPin;

    @JsonProperty("serialNumber")
    private String serialNumber;

    @JsonProperty("slot")
    private String slot;

    @JsonProperty("pin")
    private String pin;

    @JsonProperty("managementKey")
    private String managementKey;

    @JsonProperty("locality")
    private String locality;

    @JsonProperty("province")
    private String province;

    @JsonProperty("country")
    private String country;

    @JsonProperty("commonName")
    private String commonName;

    @JsonProperty("organization")
    private String organization;

    @JsonProperty("organizationalUnit")
    private String organizationalUnit;

    @JsonProperty("emailAddress")
    private String emailAddress;

}

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

    @JsonProperty("issuerUsbSlot")
    private String issuerUsbSlot;

    @JsonProperty("issuerPivSlot")
    private String issuerPivSlot;

    @JsonProperty("issuerPin")
    private String issuerPin;

    @JsonProperty("usbSlot")
    private String usbSlot;

    @JsonProperty("pivSlot")
    private String pivSlot;

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

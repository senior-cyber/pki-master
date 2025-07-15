package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PKCS10CertificationRequestDeserializer;
import com.senior.cyber.pki.common.converter.PKCS10CertificationRequestSerializer;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.Serializable;

@Getter
@Setter
public class JcaIssuerGenerateRequest implements Serializable {

    @JsonProperty("issuerId")
    private String issuerId;

    @JsonProperty("issuerUsbSlot")
    private String issuerUsbSlot;

    @JsonProperty("issuerPivSlot")
    private String issuerPivSlot;

    @JsonProperty("issuerPin")
    private String issuerPin;

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

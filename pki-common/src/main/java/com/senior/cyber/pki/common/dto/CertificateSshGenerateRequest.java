package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class CertificateSshGenerateRequest implements Serializable {

    @JsonProperty("issuerId")
    private String issuerId;

    @JsonProperty("issuerSerialNumber")
    private String issuerSerialNumber;

    @JsonProperty("issuerSlot")
    private String issuerSlot;

    @JsonProperty("issuerPin")
    private String issuerPin;

    @JsonProperty("issuerManagementKey")
    private String issuerManagementKey;

    @JsonProperty("opensshPublicKey")
    private String opensshPublicKey;

    @JsonProperty("principal")
    private String principal;

}

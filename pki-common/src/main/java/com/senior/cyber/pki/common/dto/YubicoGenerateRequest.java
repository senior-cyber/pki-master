package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;

import java.io.Serializable;

@Setter
@Getter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class YubicoGenerateRequest implements Serializable {

    @JsonProperty("size")
    private int size;

    @JsonProperty("format")
    private KeyFormatEnum format;

    @JsonProperty("serialNumber")
    private String serialNumber;

    @JsonProperty("slot")
    private String slot;

    @JsonProperty("managementKey")
    private String managementKey;

    @JsonProperty("emailAddress")
    private String emailAddress;

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;

import java.io.Serializable;

@Getter
@Setter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class YubicoInfo implements Serializable {

    @JsonProperty("transport")
    private String transport;

    @JsonProperty("version")
    private String version;

    @JsonProperty("serialNumber")
    private String serialNumber;

    @JsonProperty("partNumber")
    private String partNumber;

    @JsonProperty("formFactor")
    private String formFactor;

    @JsonProperty("versionName")
    private String versionName;

    @JsonProperty("type")
    private String type;

}

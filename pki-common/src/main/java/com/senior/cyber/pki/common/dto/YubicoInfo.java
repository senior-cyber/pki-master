package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class YubicoInfo {

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

}

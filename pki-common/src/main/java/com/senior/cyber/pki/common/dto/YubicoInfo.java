package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@Builder
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

    @JsonCreator
    public static YubicoInfo create() {
        return YubicoInfo.builder().build();
    }

}

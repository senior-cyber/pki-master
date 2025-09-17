package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class YubicoPassword implements Serializable {

    @JsonProperty("serial")
    private String serial;

    @JsonProperty("piv_slot")
    private String pivSlot;

    @JsonProperty("management_key")
    private String managementKey;

    @JsonProperty("pin")
    private String pin;

    @JsonCreator
    public static YubicoPassword create() {
        return YubicoPassword.builder().build();
    }

}

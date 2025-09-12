package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class YubicoPassword {

    @JsonProperty("serial")
    private String serial;

    @JsonProperty("piv_slot")
    private String pivSlot;

    @JsonProperty("management_key")
    private String managementKey;

    @JsonProperty("pin")
    private String pin;

}

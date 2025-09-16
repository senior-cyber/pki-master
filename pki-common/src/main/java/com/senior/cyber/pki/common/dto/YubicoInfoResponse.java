package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;

import java.util.ArrayList;
import java.util.List;

@Setter
@Getter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class YubicoInfoResponse extends BaseResponse {

    @JsonProperty("items")
    private List<YubicoInfo> items;

}

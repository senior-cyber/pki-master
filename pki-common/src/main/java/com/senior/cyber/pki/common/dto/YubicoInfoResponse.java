package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@Builder
public class YubicoInfoResponse extends BaseResponse {

    @JsonProperty("items")
    private List<YubicoInfo> items;

    @JsonCreator
    public static YubicoInfoResponse create() {
        return YubicoInfoResponse.builder().build();
    }

}

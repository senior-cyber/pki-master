package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Setter
@Getter
@Builder
public class YubicoInfoResponse extends BaseResponse {

    @Builder.Default
    @JsonProperty("items")
    private List<YubicoInfo> items = new ArrayList<>();

    @JsonCreator
    public static YubicoInfoResponse create() {
        return YubicoInfoResponse.builder().build();
    }

}

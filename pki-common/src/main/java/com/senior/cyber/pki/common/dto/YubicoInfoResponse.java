package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Setter
@Getter
public class YubicoInfoResponse extends BaseResponse {

    @JsonProperty("items")
    private List<YubicoInfo> items = new ArrayList<>();

}

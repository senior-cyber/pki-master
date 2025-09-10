package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class YubicoKeyGenerateResponse extends BaseResponse {

    @JsonProperty("keyId")
    private String keyId;

}

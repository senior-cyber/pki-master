package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class KeyInfoRequest extends BaseRequest {

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonCreator
    public static KeyInfoRequest create() {
        return KeyInfoRequest.builder().build();
    }

}

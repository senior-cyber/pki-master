package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class BcGenerateRequest extends BaseRequest {

    @JsonProperty("size")
    private int size;

    @JsonProperty("format")
    private KeyFormatEnum format;

    @JsonProperty("emailAddress")
    private String emailAddress;

    @JsonCreator
    public static BcGenerateRequest create() {
        return BcGenerateRequest.builder().build();
    }

}

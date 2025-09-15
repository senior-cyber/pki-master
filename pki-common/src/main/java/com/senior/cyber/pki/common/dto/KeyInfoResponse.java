package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class KeyInfoResponse extends BaseResponse {

    @JsonProperty("type")
    private KeyTypeEnum type;

    @JsonProperty("format")
    private KeyFormatEnum format;

    @JsonProperty("size")
    private Integer size;

    @JsonProperty("decentralized")
    private boolean decentralized;

}

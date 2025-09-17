package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class ServerInfoResponse extends BaseResponse {

    @JsonProperty("apiCrl")
    protected String apiCrl;

    @JsonProperty("apiOcsp")
    protected String apiOcsp;

    @JsonProperty("apiX509")
    protected String apiX509;

    @JsonCreator
    public static ServerInfoResponse create() {
        return ServerInfoResponse.builder().build();
    }

}

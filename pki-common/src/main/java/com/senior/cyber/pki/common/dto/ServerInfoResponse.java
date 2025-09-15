package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ServerInfoResponse extends BaseResponse {

    @JsonProperty("apiCrl")
    protected String apiCrl;

    @JsonProperty("apiOcsp")
    protected String apiOcsp;

    @JsonProperty("apiX509")
    protected String apiX509;

    public ServerInfoResponse() {
    }

    public ServerInfoResponse(String apiCrl, String apiOcsp, String apiX509) {
        this.apiCrl = apiCrl;
        this.apiOcsp = apiOcsp;
        this.apiX509 = apiX509;
    }

}

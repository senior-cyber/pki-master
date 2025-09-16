package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;

@Setter
@Getter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class ServerInfoResponse extends BaseResponse {

    @JsonProperty("apiCrl")
    protected String apiCrl;

    @JsonProperty("apiOcsp")
    protected String apiOcsp;

    @JsonProperty("apiX509")
    protected String apiX509;

}

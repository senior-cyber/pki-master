package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

@Setter
@Getter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class RevokeKeyResponse extends BaseResponse {

    @JsonProperty("serverTime")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private Date serverTime;

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

@Setter
@Getter
public class RevokeKeyResponse extends BaseResponse {

    @JsonProperty("serverTime")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private Date serverTime;

}

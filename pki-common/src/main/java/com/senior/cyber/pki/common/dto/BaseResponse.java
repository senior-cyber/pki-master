package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Date;

@Setter
@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class BaseResponse implements Serializable {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("timestamp")
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX", timezone = "Asia/Phnom_Penh")
    protected Date timestamp;

    @JsonProperty("status")
    protected int status = 200;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("error")
    protected String error;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("exception")
    protected String exception;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("trace")
    protected String trace;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("message")
    protected String message;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("path")
    protected String path;

}

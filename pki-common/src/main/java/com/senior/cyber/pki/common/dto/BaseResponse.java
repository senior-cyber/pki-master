package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Date;

@Setter
@Getter
public abstract class BaseResponse implements Serializable {

    @JsonProperty("timestamp")
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    protected Date timestamp;

    @JsonProperty("status")
    protected Integer status;

    @JsonProperty("error")
    protected String error;

    @JsonProperty("exception")
    protected String exception;

    @JsonProperty("trace")
    protected String trace;

    @JsonProperty("message")
    protected String message;

    @JsonProperty("path")
    protected String path;

}

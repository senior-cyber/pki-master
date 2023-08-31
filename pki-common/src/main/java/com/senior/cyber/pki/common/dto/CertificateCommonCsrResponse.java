package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class CertificateCommonCsrResponse implements Serializable {

    @JsonProperty("serial")
    private long serial;

}

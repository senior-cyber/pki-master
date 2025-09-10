package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.cert.X509Certificate;

@Setter
@Getter
public class MtlsGenerateResponse extends BaseResponse {

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("certificate")
    private X509Certificate certificate;

}

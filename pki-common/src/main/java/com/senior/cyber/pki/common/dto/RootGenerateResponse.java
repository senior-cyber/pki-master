package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.X509CertificateDeserializer;
import com.senior.cyber.pki.common.converter.X509CertificateSerializer;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.security.cert.X509Certificate;

@Setter
@Getter
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class RootGenerateResponse extends BaseResponse {

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("certificate")
    private X509Certificate certificate;

    @JsonCreator
    public static RootGenerateResponse create() {
        return RootGenerateResponse.builder().build();
    }

}

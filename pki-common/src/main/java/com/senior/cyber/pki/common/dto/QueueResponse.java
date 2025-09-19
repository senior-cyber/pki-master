package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.X509CertificateDeserializer;
import com.senior.cyber.pki.common.converter.X509CertificateSerializer;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.cert.X509Certificate;

@Setter
@Getter
@Builder
public class QueueResponse implements Serializable {

    @JsonProperty("id")
    private String id;

    @JsonProperty("subject")
    private Subject subject;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("certificate")
    private X509Certificate issuerCertificate;

    @JsonProperty("type")
    private CertificateTypeEnum type;

    @JsonProperty("keyId")
    private String keyId;

    @JsonCreator
    public static QueueResponse create() {
        return QueueResponse.builder().build();
    }

}

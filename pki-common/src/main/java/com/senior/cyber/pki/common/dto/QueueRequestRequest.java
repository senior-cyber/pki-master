package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class QueueRequestRequest extends BaseRequest {

    @JsonProperty("issuerCertificateId")
    private String issuerCertificateId;

    @JsonProperty("issuerKeyId")
    private String issuerKeyId;

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("subject")
    private Subject subject;

    @JsonProperty("type")
    private CertificateTypeEnum type;

    @JsonCreator
    public static QueueRequestRequest create() {
        return QueueRequestRequest.builder().build();
    }

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PrivateKeyDeserializer;
import com.senior.cyber.pki.common.converter.PrivateKeySerializer;
import com.senior.cyber.pki.common.converter.X509CertificateDeserializer;
import com.senior.cyber.pki.common.converter.X509CertificateSerializer;
import lombok.Getter;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Getter
@Setter
public class MtlsClientGenerateResponse extends BaseResponse{

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("cert")
    private X509Certificate cert;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("privkey")
    private PrivateKey privkey;

}

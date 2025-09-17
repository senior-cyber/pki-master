package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PrivateKeyDeserializer;
import com.senior.cyber.pki.common.converter.PrivateKeySerializer;
import com.senior.cyber.pki.common.converter.X509CertificateDeserializer;
import com.senior.cyber.pki.common.converter.X509CertificateSerializer;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Getter
@Setter
@Builder
public class SubordinateRegisterRequest extends BaseRequest {

    @JsonProperty("issuer")
    private Issuer issuer;

    @JsonProperty("key")
    private Key key;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("subordinateCertificate")
    private X509Certificate subordinateCertificate;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("crlCertificate")
    private X509Certificate crlCertificate;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("crlPrivateKey")
    private PrivateKey crlPrivateKey;

    @JsonProperty("crlKeySize")
    private Integer crlKeySize;

    @JsonProperty("crlKeyFormat")
    private KeyFormatEnum crlKeyFormat;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("ocspCertificate")
    private X509Certificate ocspCertificate;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("ocspPrivateKey")
    private PrivateKey ocspPrivateKey;

    @JsonProperty("ocspKeySize")
    private Integer ocspKeySize;

    @JsonProperty("ocspKeyFormat")
    private KeyFormatEnum ocspKeyFormat;

    @JsonCreator
    public static SubordinateRegisterRequest create() {
        return SubordinateRegisterRequest.builder().build();
    }

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.X509CertificateDeserializer;
import com.senior.cyber.pki.common.converter.X509CertificateSerializer;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.cert.X509Certificate;

@Setter
@Getter
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class Certificate implements Serializable {

    @JsonProperty("certificateId")
    private String certificateId;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("certificate")
    private X509Certificate certificate;

    @JsonProperty("keyPassword")
    private String keyPassword;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("type")
    private KeyTypeEnum type;

    @JsonProperty("decentralized")
    private boolean decentralized;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("privateKey")
    private String privateKey;

    @JsonCreator
    public static Certificate create() {
        return Certificate.builder().build();
    }

}

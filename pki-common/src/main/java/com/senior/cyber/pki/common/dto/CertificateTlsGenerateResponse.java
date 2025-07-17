package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

@Setter
@Getter
public class CertificateTlsGenerateResponse implements Serializable {

    @JsonProperty("id")
    private String id;

    @JsonSerialize(using = X509CertificateSerializer.class)
    @JsonDeserialize(using = X509CertificateDeserializer.class)
    @JsonProperty("cert")
    private X509Certificate cert;

    @JsonProperty("certBase64")
    private String certBase64;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("privkey")
    private PrivateKey privkey;

    @JsonProperty("privkeyBase64")
    private String privkeyBase64;

    @JsonSerialize(using = X509CertificatesSerializer.class)
    @JsonDeserialize(using = X509CertificatesDeserializer.class)
    private List<X509Certificate> chain;

    @JsonSerialize(using = X509CertificatesSerializer.class)
    @JsonDeserialize(using = X509CertificatesDeserializer.class)
    private List<X509Certificate> fullchain;

}

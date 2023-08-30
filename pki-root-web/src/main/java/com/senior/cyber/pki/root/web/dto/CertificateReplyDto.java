package com.senior.cyber.pki.root.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.frmk.common.jackson.CertificateDeserializer;
import com.senior.cyber.frmk.common.jackson.CertificateSerializer;

import java.security.cert.X509Certificate;

public class CertificateReplyDto {

    @JsonProperty("certificate")
    @JsonSerialize(using = CertificateSerializer.class)
    @JsonDeserialize(using = CertificateDeserializer.class)
    private X509Certificate certificate;

    public CertificateReplyDto() {
    }

    public CertificateReplyDto(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

}

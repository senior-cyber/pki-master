package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.Serializable;

@Setter
@Getter
public class CertificateCommonCsrRequest implements Serializable {

    @JsonProperty("issuerSerial")
    private long issuerSerial;

    @JsonProperty("serial")
    private long serial;

    @JsonProperty("csr")
    private PKCS10CertificationRequest csr;

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.Serializable;
import java.util.List;

@Setter
@Getter
public class CertificateTlsCsrRequest implements Serializable {

    @JsonProperty("issuerSerial")
    private long issuerSerial;

    @JsonProperty("serial")
    private long serial;

    @JsonProperty("serial")
    private PKCS10CertificationRequest csr;

    @JsonProperty("ip")
    private List<String> ip;

    @JsonProperty("dns")
    private List<String> dns;

}

package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PKCS10CertificationRequestDeserializer;
import com.senior.cyber.pki.common.converter.PKCS10CertificationRequestSerializer;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.Serializable;

@Setter
@Getter
public class CertificateCommonCsrRequest implements Serializable {

    @JsonProperty("issuerSerial")
    private long issuerSerial;

    @JsonProperty("serial")
    private long serial;

    @JsonSerialize(using = PKCS10CertificationRequestSerializer.class)
    @JsonDeserialize(using = PKCS10CertificationRequestDeserializer.class)
    @JsonProperty("csr")
    private PKCS10CertificationRequest csr;

}

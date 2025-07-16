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
import java.util.List;

@Setter
@Getter
public class CertificateTlsGenerateRequest implements Serializable {

    @JsonProperty("issuerId")
    private String issuerId;

    @JsonProperty("issuerSerialNumber")
    private String issuerSerialNumber;

    @JsonProperty("issuerSlot")
    private String issuerSlot;

    @JsonProperty("issuerPin")
    private String issuerPin;

    @JsonProperty("issuerManagementKey")
    private String issuerManagementKey;

    @JsonSerialize(using = PKCS10CertificationRequestSerializer.class)
    @JsonDeserialize(using = PKCS10CertificationRequestDeserializer.class)
    @JsonProperty("csr")
    private PKCS10CertificationRequest csr;

    @JsonProperty("locality")
    private String locality;

    @JsonProperty("province")
    private String province;

    @JsonProperty("country")
    private String country;

    @JsonProperty("commonName")
    private String commonName;

    @JsonProperty("organization")
    private String organization;

    @JsonProperty("organizationalUnit")
    private String organizationalUnit;

    @JsonProperty("emailAddress")
    private String emailAddress;

    @JsonProperty("ip")
    private List<String> ip;

    @JsonProperty("dns")
    private List<String> dns;

}

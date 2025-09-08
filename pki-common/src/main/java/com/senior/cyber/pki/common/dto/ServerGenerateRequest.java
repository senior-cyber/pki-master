package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.List;

@Setter
@Getter
public class ServerGenerateRequest implements Serializable {

    @JsonProperty("issuerCertificateId")
    private String issuerCertificateId;

    @JsonProperty("issuerKeyPassword")
    private String issuerKeyPassword;

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

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

    @JsonProperty("sans")
    private List<String> sans;

}

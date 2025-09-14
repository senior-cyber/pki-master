package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.List;

@Setter
@Getter
public class ServerGenerateRequest implements Serializable {

    @JsonProperty("issuer")
    private Issuer issuer;

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

    public ServerGenerateRequest() {
    }

    public ServerGenerateRequest(Issuer issuer, String keyId, String keyPassword, String locality, String province, String country, String commonName, String organization, String organizationalUnit, String emailAddress, List<String> sans) {
        this.issuer = issuer;
        this.keyId = keyId;
        this.keyPassword = keyPassword;
        this.locality = locality;
        this.province = province;
        this.country = country;
        this.commonName = commonName;
        this.organization = organization;
        this.organizationalUnit = organizationalUnit;
        this.emailAddress = emailAddress;
        this.sans = sans;
    }

}

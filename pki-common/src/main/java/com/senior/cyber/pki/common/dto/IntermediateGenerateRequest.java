package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.PrivateKeyDeserializer;
import com.senior.cyber.pki.common.converter.PrivateKeySerializer;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PrivateKey;

@Getter
@Setter
public class IntermediateGenerateRequest implements Serializable {

    @JsonProperty("issuerCertificateId")
    private String issuerCertificateId;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("issuerPrivateKey")
    private PrivateKey issuerPrivateKey;

    @JsonProperty("keyId")
    private String keyId;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("privateKey")
    private PrivateKey privateKey;

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

}

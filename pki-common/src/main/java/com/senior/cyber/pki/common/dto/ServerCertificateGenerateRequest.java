package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import com.senior.cyber.pki.common.x509.KeyFormat;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

@Setter
@Getter
public class ServerCertificateGenerateRequest implements Serializable {

    @JsonProperty("issuerCertificateId")
    private String issuerCertificateId;

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("issuerPrivateKey")
    private PrivateKey issuerPrivateKey;

    @JsonProperty("keyId")
    private String keyId;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonProperty("keyFormat")
    private KeyFormat keyFormat;

    @JsonProperty("keySize")
    private int keySize;

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

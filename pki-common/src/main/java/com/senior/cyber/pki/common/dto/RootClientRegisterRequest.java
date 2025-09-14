package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Setter
@Getter
public class RootClientRegisterRequest implements Serializable {

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("keyPassword")
    private String keyPassword;

    private X509Certificate certificate;

    private X509Certificate crlCertificate;
    private PrivateKey crlPrivateKey;

    private X509Certificate ocspCertificate;
    private PrivateKey ocspPrivateKey;

    public RootClientRegisterRequest() {
    }

    public RootClientRegisterRequest(String keyId, String keyPassword, String emailAddress) {
        this.keyId = keyId;
        this.keyPassword = keyPassword;
        this.emailAddress = emailAddress;
    }

}

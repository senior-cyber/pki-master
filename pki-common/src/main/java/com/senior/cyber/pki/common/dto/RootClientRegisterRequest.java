package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.senior.cyber.pki.common.x509.KeyFormat;
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

    private X509Certificate rootCertificate;

    private X509Certificate crlCertificate;
    private PrivateKey crlPrivateKey;
    private Integer crlKeySize;
    private KeyFormat crlKeyFormat;

    private X509Certificate ocspCertificate;
    private PrivateKey ocspPrivateKey;
    private Integer ocspKeySize;
    private KeyFormat ocspKeyFormat;

    public RootClientRegisterRequest() {
    }

    public RootClientRegisterRequest(String keyId, String keyPassword) {
        this.keyId = keyId;
        this.keyPassword = keyPassword;
    }

}

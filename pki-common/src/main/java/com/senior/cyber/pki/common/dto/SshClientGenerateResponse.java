package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import lombok.Getter;
import lombok.Setter;
import org.apache.sshd.common.config.keys.OpenSshCertificate;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

@Setter
@Getter
public class SshClientGenerateResponse implements Serializable {

    @JsonProperty("id_rsa-cert.pub")
    @JsonSerialize(using = OpenSshCertificateSerializer.class)
    @JsonDeserialize(using = OpenSshCertificateDeserializer.class)
    private OpenSshCertificate certificate;

    @JsonProperty("id_rsa.pub")
    @JsonSerialize(using = OpenSshPublicKeySerializer.class)
    @JsonDeserialize(using = OpenSshPublicKeyDeserializer.class)
    private PublicKey publicKey;

    @JsonSerialize(using = OpenSshPrivateKeySerializer.class)
    @JsonDeserialize(using = OpenSshPrivateKeyDeserializer.class)
    @JsonProperty("id_rsa")
    private PrivateKey privateKey;

    @JsonProperty("opensshConfig")
    private String opensshConfig;

}

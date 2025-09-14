package com.senior.cyber.pki.client.cli.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

@Getter
@Setter
public class BcClientGenerate implements Serializable {

    @JsonProperty("publicKey")
    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    private PublicKey publicKey;

    @JsonProperty("privateKey")
    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    private PrivateKey privateKey;

    @JsonProperty("openSshPublicKey")
    @JsonSerialize(using = OpenSshPublicKeySerializer.class)
    @JsonDeserialize(using = OpenSshPublicKeyDeserializer.class)
    private PublicKey openSshPublicKey;

    @JsonProperty("openSshPrivateKey")
    @JsonSerialize(using = OpenSshPrivateKeySerializer.class)
    @JsonDeserialize(using = OpenSshPrivateKeyDeserializer.class)
    private PrivateKey openSshPrivateKey;

    public BcClientGenerate() {
    }

    public BcClientGenerate(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.openSshPublicKey = publicKey;
        this.openSshPrivateKey = privateKey;
    }

}

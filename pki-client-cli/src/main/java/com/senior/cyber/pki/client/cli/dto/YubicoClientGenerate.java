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
public class YubicoClientGenerate implements Serializable {

    @JsonProperty("publicKey")
    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    private PublicKey publicKey;

    @JsonProperty("openSshPublicKey")
    @JsonSerialize(using = OpenSshPublicKeySerializer.class)
    @JsonDeserialize(using = OpenSshPublicKeyDeserializer.class)
    private PublicKey openSshPublicKey;

    public YubicoClientGenerate() {
    }

    public YubicoClientGenerate(PublicKey publicKey) {
        this.publicKey = publicKey;
        this.openSshPublicKey = publicKey;
    }

}

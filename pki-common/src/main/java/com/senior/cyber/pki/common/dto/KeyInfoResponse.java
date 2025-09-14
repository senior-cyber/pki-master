package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.*;
import lombok.Getter;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

@Setter
@Getter
public class KeyInfoResponse extends BaseResponse {

    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    @JsonProperty("privateKey")
    private PrivateKey privateKey;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonSerialize(using = OpenSshPublicKeySerializer.class)
    @JsonDeserialize(using = OpenSshPublicKeyDeserializer.class)
    @JsonProperty("openSshPublicKey")
    private PublicKey openSshPublicKey;

    @JsonSerialize(using = OpenSshPrivateKeySerializer.class)
    @JsonDeserialize(using = OpenSshPrivateKeyDeserializer.class)
    @JsonProperty("openSshPrivateKey")
    private PrivateKey openSshPrivateKey;

    @JsonProperty("type")
    private String type;

    @JsonProperty("keyFormat")
    private String keyFormat;

    @JsonProperty("keySize")
    private Integer keySize;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd", timezone = "Asia/Phnom_Penh")
    @JsonProperty("createdDatetime")
    private Date createdDatetime;

}

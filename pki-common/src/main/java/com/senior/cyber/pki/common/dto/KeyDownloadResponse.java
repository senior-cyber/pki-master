package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.OpenSshPublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.OpenSshPublicKeySerializer;
import com.senior.cyber.pki.common.converter.PublicKeyDeserializer;
import com.senior.cyber.pki.common.converter.PublicKeySerializer;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import lombok.Getter;
import lombok.Setter;

import java.security.PublicKey;
import java.util.Date;

@Setter
@Getter
public class KeyDownloadResponse extends BaseResponse {

    @JsonProperty("privateKey")
    private String privateKey;

    @JsonSerialize(using = PublicKeySerializer.class)
    @JsonDeserialize(using = PublicKeyDeserializer.class)
    @JsonProperty("publicKey")
    private PublicKey publicKey;

    @JsonSerialize(using = OpenSshPublicKeySerializer.class)
    @JsonDeserialize(using = OpenSshPublicKeyDeserializer.class)
    @JsonProperty("openSshPublicKey")
    private PublicKey openSshPublicKey;

    @JsonProperty("openSshPrivateKey")
    private String openSshPrivateKey;

    @JsonProperty("type")
    private KeyTypeEnum type;

    @JsonProperty("keyFormat")
    private KeyFormatEnum keyFormat;

    @JsonProperty("keySize")
    private Integer keySize;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd", timezone = "Asia/Phnom_Penh")
    @JsonProperty("createdDatetime")
    private Date createdDatetime;

}

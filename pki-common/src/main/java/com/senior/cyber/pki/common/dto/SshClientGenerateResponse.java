package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.pki.common.converter.OpenSshCertificateDeserializer;
import com.senior.cyber.pki.common.converter.OpenSshCertificateSerializer;
import lombok.Getter;
import lombok.Setter;
import org.apache.sshd.common.config.keys.OpenSshCertificate;

import java.io.Serializable;

@Setter
@Getter
public class SshClientGenerateResponse implements Serializable {

    @JsonProperty("opensshCertificate")
    @JsonSerialize(using = OpenSshCertificateSerializer.class)
    @JsonDeserialize(using = OpenSshCertificateDeserializer.class)
    private OpenSshCertificate opensshCertificate;

    @JsonProperty("opensshConfig")
    private String opensshConfig;

}

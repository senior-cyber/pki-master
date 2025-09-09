package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.senior.cyber.pki.common.x509.OpenSshCertificateUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;

import java.io.IOException;

public class OpenSshCertificateDeserializer extends JsonDeserializer<OpenSshCertificate> {

    @Override
    public OpenSshCertificate deserialize(JsonParser json, DeserializationContext context) throws IOException {
        String value = json.getValueAsString();
        if (value == null || value.isBlank()) {
            return null;
        }
        return OpenSshCertificateUtils.convert(value);
    }

}

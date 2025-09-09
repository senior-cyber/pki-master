package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.senior.cyber.pki.common.x509.OpenSshCertificateUtils;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.OpenSshCertificate;

import java.io.IOException;

public class OpenSshCertificateSerializer extends JsonSerializer<OpenSshCertificate> {

    @Override
    public void serialize(OpenSshCertificate object, JsonGenerator json, SerializerProvider provider) throws IOException {
        if (object == null) {
            json.writeNull();
        } else {
            json.writeString(OpenSshCertificateUtils.convert(object));
        }
    }

}

package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.senior.cyber.pki.common.x509.OpenSshPrivateKeyUtils;

import java.io.IOException;
import java.security.PrivateKey;

public class OpenSshPrivateKeySerializer extends JsonSerializer<PrivateKey> {

    @Override
    public void serialize(PrivateKey object, JsonGenerator json, SerializerProvider provider) throws IOException {
        if (object == null) {
            json.writeNull();
        } else {
            json.writeString(OpenSshPrivateKeyUtils.convert(object));
        }
    }

}

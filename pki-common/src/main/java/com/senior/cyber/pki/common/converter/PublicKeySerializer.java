package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.senior.cyber.pki.common.x509.PublicKeyUtils;

import java.io.IOException;
import java.security.PublicKey;

public class PublicKeySerializer extends JsonSerializer<PublicKey> {

    @Override
    public void serialize(PublicKey object, JsonGenerator json, SerializerProvider provider) throws IOException {
        if (object == null) {
            json.writeNull();
        } else {
            json.writeString(PublicKeyUtils.convert(object));
        }
    }

}

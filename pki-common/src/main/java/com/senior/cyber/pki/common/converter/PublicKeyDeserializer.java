package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.senior.cyber.pki.common.x509.PublicKeyUtils;

import java.io.IOException;
import java.security.PublicKey;

public class PublicKeyDeserializer extends JsonDeserializer<PublicKey> {

    @Override
    public PublicKey deserialize(JsonParser json, DeserializationContext context) throws IOException {
        String value = json.getValueAsString();
        if (value == null || value.isBlank()) {
            return null;
        }
        return PublicKeyUtils.convert(value);
    }

}

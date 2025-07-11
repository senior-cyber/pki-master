package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;

import java.io.IOException;
import java.security.PrivateKey;

public class PrivateKeyDeserializer extends JsonDeserializer<PrivateKey> {

    @Override
    public PrivateKey deserialize(JsonParser json, DeserializationContext context) throws IOException {
        String value = json.getValueAsString();
        if (value == null || value.isBlank()) {
            return null;
        }
        return PrivateKeyUtils.convert(value);
    }

}

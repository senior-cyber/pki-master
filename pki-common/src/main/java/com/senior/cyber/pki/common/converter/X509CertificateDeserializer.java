package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.senior.cyber.pki.common.x509.CertificateUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;

public class X509CertificateDeserializer extends JsonDeserializer<X509Certificate> {

    @Override
    public X509Certificate deserialize(JsonParser json, DeserializationContext context) throws IOException {
        String value = json.getValueAsString();
        if (value == null || value.isBlank()) {
            return null;
        }
        return CertificateUtils.convert(value);
    }

}

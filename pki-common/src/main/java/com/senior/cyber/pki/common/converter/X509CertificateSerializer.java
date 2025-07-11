package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.senior.cyber.pki.common.x509.CertificateUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;

public class X509CertificateSerializer extends JsonSerializer<X509Certificate> {

    @Override
    public void serialize(X509Certificate object, JsonGenerator json, SerializerProvider provider) throws IOException {
        if (object == null) {
            json.writeNull();
        } else {
            json.writeString(CertificateUtils.convert(object));
        }
    }

}

package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.senior.cyber.pki.common.x509.CertificateUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

public class X509CertificatesSerializer extends JsonSerializer<List<X509Certificate>> {

    @Override
    public void serialize(List<X509Certificate> object, JsonGenerator json, SerializerProvider provider) throws IOException {
        if (object == null) {
            json.writeNull();
        } else {
            StringBuilder buffer = new StringBuilder();
            for (X509Certificate certificate : object) {
                buffer.append(CertificateUtils.convert(certificate));
            }
            json.writeString(buffer.toString());
        }
    }

}

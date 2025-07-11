package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.senior.cyber.pki.common.x509.CertificateUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class X509CertificatesDeserializer extends JsonDeserializer<List<X509Certificate>> {

    @Override
    public List<X509Certificate> deserialize(JsonParser json, DeserializationContext context) throws IOException {
        String value = json.getValueAsString();
        if (value == null || value.isBlank()) {
            return null;
        }
        List<X509Certificate> certificates = new ArrayList<>();
        String[] values = value.split("-----END CERTIFICATE-----");
        for (String v : values) {
            X509Certificate x509 = CertificateUtils.convert(v + "-----END CERTIFICATE-----");
            certificates.add(x509);
        }
        return certificates;
    }

}

package com.senior.cyber.pki.dao.type;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.io.IOException;
import java.security.cert.X509Certificate;

@Converter
public class CertificateAttributeConverter implements AttributeConverter<X509Certificate, String> {

    @Override
    public String convertToDatabaseColumn(X509Certificate attribute) {
        if (attribute == null) {
            return null;
        }
        try {
            return CertificateSerializer.convert(attribute);
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public X509Certificate convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isEmpty()) {
            return null;
        }
        try {
            return CertificateDeserializer.convert(dbData);
        } catch (IOException e) {
            return null;
        }
    }

}

package com.senior.cyber.pki.dao.type;

import com.senior.cyber.pki.common.x509.CertificateUtils;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.security.cert.X509Certificate;

@Converter
public class X509CertificateType implements AttributeConverter<X509Certificate, String> {

    @Override
    public String convertToDatabaseColumn(X509Certificate value) {
        return CertificateUtils.convert(value);
    }

    @Override
    public X509Certificate convertToEntityAttribute(String value) {
        return CertificateUtils.convert(value);
    }


}

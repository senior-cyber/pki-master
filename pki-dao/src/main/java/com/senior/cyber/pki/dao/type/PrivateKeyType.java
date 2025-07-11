package com.senior.cyber.pki.dao.type;

import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.security.PrivateKey;

@Converter
public class PrivateKeyType implements AttributeConverter<PrivateKey, String> {

    @Override
    public String convertToDatabaseColumn(PrivateKey value) {
        return PrivateKeyUtils.convert(value);
    }

    @Override
    public PrivateKey convertToEntityAttribute(String value) {
        return PrivateKeyUtils.convert(value);
    }

}

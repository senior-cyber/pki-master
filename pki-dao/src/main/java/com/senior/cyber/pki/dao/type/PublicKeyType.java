package com.senior.cyber.pki.dao.type;

import com.senior.cyber.pki.common.x509.PublicKeyUtils;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.security.PublicKey;

@Converter
public class PublicKeyType implements AttributeConverter<PublicKey, String> {

    @Override
    public String convertToDatabaseColumn(PublicKey value) {
        return PublicKeyUtils.convert(value);
    }

    @Override
    public PublicKey convertToEntityAttribute(String value) {
        return PublicKeyUtils.convert(value);
    }

}

package com.senior.cyber.pki.dao.type;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.io.IOException;
import java.security.PrivateKey;

@Converter
public class PrivateKeyAttributeConverter implements AttributeConverter<PrivateKey, String> {

    @Override
    public String convertToDatabaseColumn(PrivateKey attribute) {
        if (attribute == null) {
            return null;
        }
        try {
            return PrivateKeySerializer.convert(attribute);
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public PrivateKey convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isEmpty()) {
            return null;
        }
        try {
            return PrivateKeyDeserializer.convert(dbData);
        } catch (IOException e) {
            return null;
        }
    }

}

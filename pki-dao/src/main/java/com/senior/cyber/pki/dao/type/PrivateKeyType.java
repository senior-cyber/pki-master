package com.senior.cyber.pki.dao.type;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;

@Converter
public class PrivateKeyType implements AttributeConverter<PrivateKey, String> {

    @Override
    public String convertToDatabaseColumn(PrivateKey value) {
        return convert(value);
    }

    @Override
    public PrivateKey convertToEntityAttribute(String value) {
        return convert(value);
    }

    public static PrivateKey convert(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object objectHolder = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (objectHolder instanceof PEMKeyPair holder) {
                return converter.getPrivateKey(holder.getPrivateKeyInfo());
            } else if (objectHolder instanceof PrivateKeyInfo holder) {
                return converter.getPrivateKey(holder);
            } else {
                throw new UnsupportedOperationException(objectHolder.getClass().getName());
            }
        } catch (IOException e) {
            return null;
        }
    }

    public static String convert(PrivateKey value) {
        if (value == null) {
            return null;
        }
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(new JcaPKCS8Generator(value, null));
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

}

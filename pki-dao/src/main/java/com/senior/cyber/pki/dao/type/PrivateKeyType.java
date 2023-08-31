package com.senior.cyber.pki.dao.type;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;

@Converter
public class PrivateKeyType implements AttributeConverter<PrivateKey, String> {

    private static final String password = "password";
    private static final InputDecryptorProvider decryptor;
    private static final OutputEncryptor encryptor;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        boolean enabled = false;

        InputDecryptorProvider _decryptor = null;
        OutputEncryptor _encryptor = null;
        try {
            JceOpenSSLPKCS8DecryptorProviderBuilder decryptorBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
            decryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            _decryptor = decryptorBuilder.build(password.toCharArray());

            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC);
            encryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            encryptorBuilder.setRandom(new SecureRandom());
            encryptorBuilder.setPassword(password.toCharArray());
            encryptorBuilder.setIterationCount(10000);
            _encryptor = encryptorBuilder.build();
        } catch (OperatorCreationException e) {
            e.getMessage();
        }

        if (enabled && _decryptor != null && _encryptor != null) {
            decryptor = _decryptor;
            encryptor = _encryptor;
        } else {
            decryptor = null;
            encryptor = null;
        }
    }

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
            if (objectHolder instanceof PKCS8EncryptedPrivateKeyInfo holder) {
                PrivateKeyInfo info = holder.decryptPrivateKeyInfo(decryptor);
                return converter.getPrivateKey(info);
            } else if (objectHolder instanceof PEMKeyPair holder) {
                return converter.getPrivateKey(holder.getPrivateKeyInfo());
            } else if (objectHolder instanceof PrivateKeyInfo holder) {
                return converter.getPrivateKey(holder);
            } else {
                throw new UnsupportedOperationException(objectHolder.getClass().getName());
            }
        } catch (IOException | PKCSException e) {
            return null;
        }
    }

    public static String convert(PrivateKey value) {
        if (value == null) {
            return null;
        }
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(new JcaPKCS8Generator(value, encryptor));
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

}

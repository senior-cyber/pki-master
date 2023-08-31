package com.senior.cyber.pki.dao.type;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Converter
public class PublicKeyType implements AttributeConverter<PublicKey, String> {

    @Override
    public String convertToDatabaseColumn(PublicKey value) {
        return convert(value);
    }

    @Override
    public PublicKey convertToEntityAttribute(String value) {
        return convert(value);
    }

    public static String convert(PublicKey value) {
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(value);
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

    public static PublicKey convert(String value) {
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object object = parser.readObject();
            if (object instanceof X509CertificateHolder holder) {
                JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
                converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                X509Certificate certificate = converter.getCertificate(holder);
                return certificate.getPublicKey();
            } else if (object instanceof SubjectPublicKeyInfo holder) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                return converter.getPublicKey(holder);
            } else {
                throw new java.lang.UnsupportedOperationException(object.getClass().getName());
            }
        } catch (CertificateException | IOException e) {
            return null;
        }
    }

}

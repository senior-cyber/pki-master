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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Converter
public class CsrType implements AttributeConverter<PKCS10CertificationRequest, String> {

    @Override
    public String convertToDatabaseColumn(PKCS10CertificationRequest value) {
        return convert(value);
    }

    @Override
    public PKCS10CertificationRequest convertToEntityAttribute(String value) {
        return convert(value);
    }

    public static String convert(PKCS10CertificationRequest value) {
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(value);
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

    public static PKCS10CertificationRequest convert(String value) {
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object object = parser.readObject();
            if (object instanceof PKCS10CertificationRequest holder) {
                return holder;
            } else {
                throw new UnsupportedOperationException(object.getClass().getName());
            }
        } catch (IOException e) {
            return null;
        }
    }

}

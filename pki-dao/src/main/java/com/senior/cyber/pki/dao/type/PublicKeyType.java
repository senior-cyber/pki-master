package com.senior.cyber.pki.dao.type;

import com.senior.cyber.pki.common.x509.PublicKeyUtils;
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
        return PublicKeyUtils.convert(value);
    }

    @Override
    public PublicKey convertToEntityAttribute(String value) {
        return PublicKeyUtils.convert(value);
    }

}

package com.senior.cyber.pki.web.gson;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class PublicKeyTypeAdapter extends TypeAdapter<PublicKey> {

    @Override
    public void write(JsonWriter out, PublicKey value) throws IOException {
        if (value != null) {
            StringWriter pem = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
                writer.writeObject(value);
            }
            out.value(pem.toString());
        } else {
            out.nullValue();
        }
    }

    @Override
    public PublicKey read(JsonReader in) throws IOException {
        String pem = in.nextString();
        try (StringReader reader = new StringReader(pem)) {
            try (PEMParser parser = new PEMParser(reader)) {
                Object object = parser.readObject();
                if (object instanceof X509CertificateHolder) {
                    X509CertificateHolder holder = (X509CertificateHolder) object;
                    X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(holder);
                    return certificate.getPublicKey();
                } else if (object instanceof SubjectPublicKeyInfo) {
                    SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) object;
                    return new JcaPEMKeyConverter().getPublicKey(subjectPublicKeyInfo);
                } else {
                    throw new IllegalArgumentException(pem + " is not readable");
                }
            } catch (CertificateException e) {
                throw new IOException(e);
            }
        }
    }

}

package com.senior.cyber.pki.web.gson;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;

public class PrivateKeyTypeAdapter extends TypeAdapter<PrivateKey> {

    @Override
    public void write(JsonWriter out, PrivateKey value) throws IOException {
        if (value != null) {
            StringWriter pem = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
                writer.writeObject(new JcaPKCS8Generator(value, null));
            }
            out.value(pem.toString());
        } else {
            out.nullValue();
        }
    }

    @Override
    public PrivateKey read(JsonReader in) throws IOException {
        String pem = in.nextString();
        try (StringReader reader = new StringReader(pem)) {
            try (PEMParser parser = new PEMParser(reader)) {
                Object objectHolder = parser.readObject();
                if (objectHolder instanceof PEMKeyPair) {
                    PEMKeyPair holder = (PEMKeyPair) objectHolder;
                    return new JcaPEMKeyConverter().getPrivateKey(holder.getPrivateKeyInfo());
                } else if (objectHolder instanceof PrivateKeyInfo) {
                    PrivateKeyInfo holder = (PrivateKeyInfo) objectHolder;
                    return new JcaPEMKeyConverter().getPrivateKey(holder);
                } else {
                    throw new IllegalArgumentException(pem + " is not readable");
                }
            }
        }
    }

}

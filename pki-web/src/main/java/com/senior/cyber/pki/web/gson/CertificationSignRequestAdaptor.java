package com.senior.cyber.pki.web.gson;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

public class CertificationSignRequestAdaptor extends TypeAdapter<PKCS10CertificationRequest> {

    @Override
    public void write(JsonWriter out, PKCS10CertificationRequest csr) throws IOException {
        if (csr == null) {
            out.nullValue();
        } else {
            StringWriter pem = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
                writer.writeObject(csr);
            }
            out.value(pem.toString());
        }
    }

    @Override
    public PKCS10CertificationRequest read(JsonReader in) throws IOException {
        String pem = in.nextString();
        StringReader reader = new StringReader(pem);
        try (PEMParser pemParser = new PEMParser(reader)) {
            Object o = pemParser.readObject();
            return (PKCS10CertificationRequest) o;
        }
    }

}

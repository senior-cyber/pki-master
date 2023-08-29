package com.senior.cyber.pki.dao.type;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.security.Security;
import java.security.cert.X509Certificate;

public class CertificateSerializer extends StdSerializer<X509Certificate> {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public CertificateSerializer() {
        super(X509Certificate.class);
    }

    @Override
    public void serialize(X509Certificate value, JsonGenerator json, SerializerProvider provider) throws IOException {
        if (value == null) {
            json.writeNull();
        } else {
            json.writeString(convert(value));
        }
    }

    public static String convert(X509Certificate value) throws IOException {
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(value);
        }
        return pem.toString();
    }

}

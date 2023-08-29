package com.senior.cyber.pki.dao.type;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;

import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.Security;

public class PrivateKeySerializer extends StdSerializer<PrivateKey> {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public PrivateKeySerializer() {
        super(PrivateKey.class);
    }

    @Override
    public void serialize(PrivateKey value, JsonGenerator json, SerializerProvider provider) throws IOException {
        if (value == null) {
            json.writeNull();
        } else {
            json.writeString(convert(value));
        }
    }

    public static String convert(PrivateKey value) throws IOException {
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(new JcaPKCS8Generator(value, null));
        }
        return pem.toString();
    }

}

package com.senior.cyber.pki.dao.type;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.Security;

public class PrivateKeyDeserializer extends StdDeserializer<PrivateKey> {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public PrivateKeyDeserializer() {
        super(PrivateKey.class);
    }

    @Override
    public PrivateKey deserialize(JsonParser json, DeserializationContext context) throws IOException {
        String pem = json.readValueAs(String.class);
        if (!StringUtils.isEmpty(pem)) {
            return convert(pem);
        }
        return null;
    }

    public static PrivateKey convert(String value) throws IOException {
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
        }
    }

}

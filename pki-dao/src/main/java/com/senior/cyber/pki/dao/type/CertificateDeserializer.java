package com.senior.cyber.pki.dao.type;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.io.StringReader;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateDeserializer extends StdDeserializer<X509Certificate> {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public CertificateDeserializer() {
        super(X509Certificate.class);
    }

    @Override
    public X509Certificate deserialize(JsonParser json, DeserializationContext context) throws IOException {
        String pem = json.readValueAs(String.class);
        if (!StringUtils.isEmpty(pem)) {
            return convert(pem);
        }
        return null;
    }

    public static X509Certificate convert(String value) throws IOException {
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object object = parser.readObject();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (object instanceof JcaX509CertificateHolder holder) {
                return converter.getCertificate(holder);
            } else if (object instanceof X509CertificateHolder holder) {
                return converter.getCertificate(holder);
            } else {
                throw new UnsupportedOperationException(object.getClass().getName());
            }
        } catch (CertificateException e) {
            throw new IOException(e);
        }
    }

}

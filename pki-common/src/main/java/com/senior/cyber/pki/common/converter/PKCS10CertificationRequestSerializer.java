package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.senior.cyber.pki.common.x509.CsrUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;

public class PKCS10CertificationRequestSerializer extends JsonSerializer<PKCS10CertificationRequest> {

    @Override
    public void serialize(PKCS10CertificationRequest csr, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        if (csr == null) {
            gen.writeNull();
        } else {
            gen.writeString(CsrUtils.convert(csr));
        }
    }

}
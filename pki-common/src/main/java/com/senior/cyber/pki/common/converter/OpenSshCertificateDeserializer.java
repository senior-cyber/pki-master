package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

public class OpenSshCertificateDeserializer extends JsonDeserializer<OpenSshCertificate> {

    @Override
    public OpenSshCertificate deserialize(JsonParser json, DeserializationContext context) throws IOException {
//        String value = json.getValueAsString();
//        if (value == null || value.isBlank()) {
//            return null;
//        }
//        List<AuthorizedKeyEntry> authorizedKeyEntries = AuthorizedKeyEntry.readAuthorizedKeys(new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)), true);
//        try {
//            authorizedKeyEntries.getFirst().resolvePublicKey(null, PublicKeyEntryResolver.IGNORING);
//            return null;
//        } catch (GeneralSecurityException e) {
//            throw new IOException(e);
//        }
        // TODO:
        return null;
    }

}

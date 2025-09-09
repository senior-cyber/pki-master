package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class OpenSshPrivateKeyDeserializer extends JsonDeserializer<PrivateKey> {

    @Override
    public PrivateKey deserialize(JsonParser json, DeserializationContext context) throws IOException {
        String value = json.getValueAsString();
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            Collection<KeyPair> _pairs = OpenSSHKeyPairResourceParser.INSTANCE.loadKeyPairs(null, null, FilePasswordProvider.EMPTY, value);
            List<KeyPair> pairs = new ArrayList<>(_pairs);
            return pairs.getFirst().getPrivate();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

}

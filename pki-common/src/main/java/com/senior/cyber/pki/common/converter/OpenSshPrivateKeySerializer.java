package com.senior.cyber.pki.common.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyEncryptionContext;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class OpenSshPrivateKeySerializer extends JsonSerializer<PrivateKey> {

    @Override
    public void serialize(PrivateKey object, JsonGenerator json, SerializerProvider provider) throws IOException {
        if (object == null) {
            json.writeNull();
        } else {
            try {
                OpenSSHKeyEncryptionContext ctx = new OpenSSHKeyEncryptionContext();
                PublicKey publicKey = KeyUtils.recoverPublicKey(object);
                KeyPair kp = new KeyPair(publicKey, object);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                OpenSSHKeyPairResourceWriter writer = new OpenSSHKeyPairResourceWriter();
                writer.writePrivateKey(kp, "", ctx, bos);
                bos.close();
                String text = new String(bos.toByteArray(), StandardCharsets.UTF_8);
                json.writeString(text);
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }
    }

}

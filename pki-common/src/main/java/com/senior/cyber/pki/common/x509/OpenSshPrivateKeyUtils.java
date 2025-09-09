package com.senior.cyber.pki.common.x509;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyEncryptionContext;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class OpenSshPrivateKeyUtils {

    public static String convert(PrivateKey value) throws IOException {
        try {
            OpenSSHKeyEncryptionContext ctx = new OpenSSHKeyEncryptionContext();
            PublicKey publicKey = KeyUtils.recoverPublicKey(value);
            KeyPair kp = new KeyPair(publicKey, value);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            OpenSSHKeyPairResourceWriter writer = new OpenSSHKeyPairResourceWriter();
            writer.writePrivateKey(kp, "", ctx, bos);
            bos.close();
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    public static PrivateKey convert(String value) throws IOException {
        try {
            Collection<KeyPair> _pairs = OpenSSHKeyPairResourceParser.INSTANCE.loadKeyPairs(null, null, FilePasswordProvider.EMPTY, value);
            List<KeyPair> pairs = new ArrayList<>(_pairs);
            return pairs.getFirst().getPrivate();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

}

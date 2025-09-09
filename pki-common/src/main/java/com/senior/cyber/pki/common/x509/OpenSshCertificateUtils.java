package com.senior.cyber.pki.common.x509;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

public class OpenSshCertificateUtils {

    public static String convert(OpenSshCertificate value) {
        return AuthorizedKeyEntry.toString(value);
    }

    public static OpenSshCertificate convert(String value) throws IOException {
        List<AuthorizedKeyEntry> authorizedKeyEntries = AuthorizedKeyEntry.readAuthorizedKeys(new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)), true);
        try {
            return (OpenSshCertificate) authorizedKeyEntries.getFirst().resolvePublicKey(null, PublicKeyEntryResolver.IGNORING);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

}

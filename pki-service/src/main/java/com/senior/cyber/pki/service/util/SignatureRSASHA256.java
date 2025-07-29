package com.senior.cyber.pki.service.util;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.SignatureRSA;

import java.security.*;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SignatureRSASHA256 extends SignatureRSA {

    private final Provider provider;

    public static final String ALGORITHM = "SHA256withRSA";

    public SignatureRSASHA256(Provider provider) {
        super(ALGORITHM, KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS);
        this.provider = provider;
    }

    @Override
    protected Signature doInitSignature(SessionContext session, String algo, Key key, boolean forSigning) throws GeneralSecurityException {
        return Signature.getInstance(algo, this.provider);
    }

}
package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface IssuerService {

    JcaIssuerGenerateResponse issuerGenerate(User user, JcaIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api, String sshApi, Slot issuerPivSlot) throws PEMException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException;

    YubicoIssuerGenerateResponse issuerGenerate(User user, YubicoIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api, String sshApi, Slot issuerPivSlot, Slot pivSlot);

}

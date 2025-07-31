package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface CertificateService {

    LeafGenerateResponse certificateCommonGenerate(User user, LeafGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException;

    ServerCertificateGenerateResponse certificateTlsServerGenerate(User user, ServerCertificateGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException;

    ServerCertificateGenerateResponse certificateTlsClientGenerate(User user, ServerCertificateGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException;

    SshCertificateGenerateResponse certificateSshGenerate(User user, SshCertificateGenerateRequest request);

}

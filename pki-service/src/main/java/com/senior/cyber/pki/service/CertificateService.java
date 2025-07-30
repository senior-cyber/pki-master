package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface CertificateService {

    CertificateCommonGenerateResponse certificateCommonGenerate(User user, CertificateCommonGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException;

    CertificateTlsGenerateResponse certificateTlsServerGenerate(User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException;

    CertificateTlsGenerateResponse certificateTlsClientGenerate(User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException;

    CertificateSshGenerateResponse certificateSshGenerate(User user, CertificateSshGenerateRequest request);

}

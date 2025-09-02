package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface CertificateService {

    LeafGenerateResponse leafGenerate(User user, LeafGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

    LeafGenerateResponse serverGenerate(User user, ServerCertificateGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

    LeafGenerateResponse clientGenerate(User user, LeafGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, BadResponseException, ApduException, ApplicationNotAvailableException;

    SshCertificateGenerateResponse sshGenerate(User user, SshCertificateGenerateRequest request) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}

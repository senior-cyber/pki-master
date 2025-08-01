package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.IntermediateGenerateRequest;
import com.senior.cyber.pki.common.dto.IntermediateGenerateResponse;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface IntermediateService {

    IntermediateGenerateResponse intermediateGenerate(User user, IntermediateGenerateRequest request, String crlApi, String ocspApi, String x509Api, String sshApi) throws IOException, ApduException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException;

}

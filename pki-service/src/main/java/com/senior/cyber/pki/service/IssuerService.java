package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.IssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.IssuerGenerateResponse;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface IssuerService {

    IssuerGenerateResponse issuerGenerate(IssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws IOException, ApduException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException;

}

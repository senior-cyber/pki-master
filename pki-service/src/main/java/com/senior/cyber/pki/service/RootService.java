package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.RootClientRegisterRequest;
import com.senior.cyber.pki.common.dto.RootServerGenerateRequest;
import com.senior.cyber.pki.common.dto.RootServerGenerateResponse;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface RootService {

    RootServerGenerateResponse rootServerGenerate(RootServerGenerateRequest request) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

    RootServerGenerateResponse rootClientRegister(String crlUrl, String ocspUrl, String x509Url, RootClientRegisterRequest request) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}

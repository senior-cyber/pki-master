package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.SubordinateGenerateRequest;
import com.senior.cyber.pki.common.dto.SubordinateGenerateResponse;
import com.senior.cyber.pki.common.dto.SubordinateRegisterRequest;
import com.senior.cyber.pki.common.dto.SubordinateRegisterResponse;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public interface SubordinateService {

    SubordinateGenerateResponse subordinateGenerate(SubordinateGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws IOException, ApduException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException;

    SubordinateRegisterResponse subordinateRegister(SubordinateRegisterRequest request, String crlApi, String ocspApi, String x509Api) throws IOException, ApduException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException, SignatureException, InvalidKeyException;

}

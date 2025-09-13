package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.MtlsClientGenerateRequest;
import com.senior.cyber.pki.common.dto.MtlsClientGenerateResponse;
import com.senior.cyber.pki.common.dto.MtlsGenerateRequest;
import com.senior.cyber.pki.common.dto.MtlsGenerateResponse;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface MtlsService {

    MtlsGenerateResponse mtlsGenerate(MtlsGenerateRequest request) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

    MtlsClientGenerateResponse mtlsClientGenerate(MtlsClientGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}

package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface LeafService {

    ServerGenerateResponse serverGenerate(ServerGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

    SshClientGenerateResponse sshClientGenerate(SshClientGenerateRequest request) throws Exception;

    MtlsClientGenerateResponse mtlsClientGenerate(MtlsClientGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}

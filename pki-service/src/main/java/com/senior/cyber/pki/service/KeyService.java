package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;

public interface KeyService {

    KeyGenerateResponse bcGenerate(KeyBcGenerateRequest request) throws OperatorCreationException;

    KeyGenerateResponse yubicoGenerate(KeyBcGenerateRequest request) throws OperatorCreationException;

    KeyBcClientRegisterResponse yubicoRegister(KeyBcClientRegisterRequest request);

    KeyBcClientRegisterResponse bcRegister(KeyBcClientRegisterRequest request);

    KeyGenerateResponse yubicoGenerate(YubicoGenerateRequest request) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException;

    KeyGenerateResponse yubicoRegister(YubicoRegisterRequest request) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}

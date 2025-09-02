package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;

import java.io.IOException;

public interface KeyService {

    JcaKeyGenerateResponse generate(JcaKeyGenerateRequest request, User user);

    YubicoKeyGenerateResponse generate(YubicoKeyGenerateRequest request, User user) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException;

    JcaKeyRegisterResponse register(JcaKeyRegisterRequest request, User user);

    YubicoKeyRegisterResponse register(YubicoKeyRegisterRequest request, User user) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}

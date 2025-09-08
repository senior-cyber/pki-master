package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.SshCAGenerateRequest;
import com.senior.cyber.pki.common.dto.SshCAGenerateResponse;
import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.common.x509.KeyUtils;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyUsageEnum;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SshCAService;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyPair;
import java.util.Date;

@Service
public class SshCAServiceImpl implements SshCAService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshCAServiceImpl.class);

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public SshCAGenerateResponse sshcaGenerate(SshCAGenerateRequest request, String sshApi) throws OperatorCreationException {
        switch (request.getSize()) {
            case 1024, 2048 -> {
                String password = RandomStringUtils.secureStrong().nextAlphanumeric(20);
                KeyPair _key = KeyUtils.generate(KeyFormat.RSA, request.getSize());
                Key key = new Key();
                key.setPrivateKey(PrivateKeyUtils.convert(_key.getPrivate(), password));
                key.setPublicKey(_key.getPublic());
                key.setType(KeyTypeEnum.ServerKeyJCE);
                key.setKeySize(request.getSize());
                key.setKeyFormat(KeyFormat.RSA);
                key.setUsage(KeyUsageEnum.SSH);
                key.setCreatedDatetime(new Date());
                this.keyRepository.save(key);

                SshCAGenerateResponse response = new SshCAGenerateResponse();
                response.setKeyPassword(password);
                response.setKeyId(key.getId());
                response.setSshCa(sshApi + "/" + key.getId() + ".pub");
                return response;
            }
            default -> {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

    }

}

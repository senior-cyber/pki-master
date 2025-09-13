package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.SshClientGenerateRequest;
import com.senior.cyber.pki.common.dto.SshClientGenerateResponse;

public interface SshCAService {

    SshClientGenerateResponse sshClientGenerate(SshClientGenerateRequest request) throws Exception;

}

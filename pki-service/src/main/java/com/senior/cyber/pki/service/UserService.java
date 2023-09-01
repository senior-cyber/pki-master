package com.senior.cyber.pki.service;

import com.google.common.io.BaseEncoding;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.repository.UserRepository;
import org.apache.commons.lang3.StringUtils;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.util.password.PasswordEncryptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected PasswordEncryptor passwordEncryptor;

    public User authenticate(String authorization) throws ResponseStatusException {
        if (authorization == null || authorization.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "access denied");
        }
        if (!StringUtils.startsWithIgnoreCase(authorization, "Basic ")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "access denied");
        }
        String loginAndPassword = new String(BaseEncoding.base64().decode(authorization.substring("Basic ".length())), StandardCharsets.UTF_8);
        int colon = StringUtils.indexOf(loginAndPassword, ":");
        String login = StringUtils.substring(loginAndPassword, 0, colon);
        String password = StringUtils.substring(loginAndPassword, colon + 1);
        Optional<User> optionalUser = userRepository.findByLogin(login);

        User user = optionalUser.orElse(null);

        if (user == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "access denied");
        }

        if (!user.isEnabled()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "access denied");
        }

        try {
            if (!passwordEncryptor.checkPassword(password, user.getPassword())) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "access denied");
            }
        } catch (EncryptionOperationNotPossibleException e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "access denied");
        }
        return user;
    }

}

package com.senior.cyber.pki.web.utility;

import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.exception.UnauthorizedResponseStatusException;
import com.senior.cyber.pki.web.factory.WicketFactory;
import com.senior.cyber.pki.web.repository.UserRepository;
import org.apache.commons.lang3.StringUtils;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.text.TextEncryptor;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

public class UserUtility {

    public static User authenticate(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || "".equals(authorization)) {
            throw new UnauthorizedResponseStatusException("PKI Master");
        } else if (!authorization.startsWith("Basic ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, authorization + " is not supported");
        } else {
            String basicText = authorization.substring("Basic ".length());
            String basic = new String(Base64.getDecoder().decode(basicText), StandardCharsets.UTF_8);
            String[] basics = StringUtils.split(basic, '=');
            String login = basics[0];
            String password = basics[1];
            User user = authenticate(login, password);
            if (user == null) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN);
            }
            return user;
        }
    }

    public static User authenticate(String login, String password) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);

        Optional<User> optionalUser = userRepository.findByLogin(login);

        User user = optionalUser.orElse(null);

        if (user == null) {
            return null;
        }

        if (!user.isEnabled()) {
            return null;
        }

        PasswordEncryptor passwordEncryptor = context.getBean(PasswordEncryptor.class);
        TextEncryptor textEncryptor = context.getBean(TextEncryptor.class);

        try {
            if (!passwordEncryptor.checkPassword(password, user.getPassword())) {
                return null;
            }
        } catch (EncryptionOperationNotPossibleException e) {
            return null;
        }
        return user;
    }
}

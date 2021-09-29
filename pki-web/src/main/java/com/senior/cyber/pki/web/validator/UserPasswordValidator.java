package com.senior.cyber.pki.web.validator;

import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.frmk.common.base.WicketFactory;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.jasypt.util.password.PasswordEncryptor;
import org.springframework.context.ApplicationContext;

import java.util.Optional;

public class UserPasswordValidator implements IValidator<String> {

    private final long userId;

    public UserPasswordValidator(long userId) {
        this.userId = userId;
    }

    @Override
    public void validate(IValidatable<String> validatable) {
        String password = validatable.getValue();
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        PasswordEncryptor passwordEncryptor = context.getBean(PasswordEncryptor.class);
        Optional<User> optionalUser = userRepository.findById(userId);
        User user = optionalUser.orElseThrow();
        try {
            if (!passwordEncryptor.checkPassword(password, user.getPassword())) {
                validatable.error(new ValidationError("invalid"));
            }
        } catch (Throwable e) {
            validatable.error(new ValidationError("invalid"));
        }
    }

}

package com.senior.cyber.pki.root.web.validator;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.repository.UserRepository;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.springframework.context.ApplicationContext;

import java.util.Optional;

public class UserLoginValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String login = validatable.getValue();
        if (login != null && !login.isEmpty()) {
            ApplicationContext context = WicketFactory.getApplicationContext();
            UserRepository userRepository = context.getBean(UserRepository.class);
            Optional<User> optionalUser = userRepository.findByLogin(login);
            optionalUser.ifPresent(user -> validatable.error(new ValidationError(login + " is not available")));
        }
    }

}

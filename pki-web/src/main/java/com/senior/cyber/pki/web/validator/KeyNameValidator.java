package com.senior.cyber.pki.web.validator;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.pki.dao.entity.Key;
import com.senior.cyber.pki.web.repository.KeyRepository;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.springframework.context.ApplicationContext;

import java.util.Optional;

public class KeyNameValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String name = validatable.getValue();
        if (name != null && !"".equals(name)) {
            if (DomainValidator.getInstance().isValid(name)) {
                ApplicationContext context = WicketFactory.getApplicationContext();
                KeyRepository userRepository = context.getBean(KeyRepository.class);
                Optional<Key> optionalUser = userRepository.findByClientId(name);
                optionalUser.ifPresent(user -> validatable.error(new ValidationError(name + " is not available")));
            } else {
                validatable.error(new ValidationError(name + " is not invalid"));
            }
        }
    }

}

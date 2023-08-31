package com.senior.cyber.pki.root.web.validator;

import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;

public class KeyNameValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String name = validatable.getValue();
//        if (name != null && !"".equals(name)) {
//            if (DomainValidator.getInstance().isValid(name)) {
//                ApplicationContext context = WicketFactory.getApplicationContext();
//                KeyRepository userRepository = context.getBean(KeyRepository.class);
//                Optional<Key> optionalUser = userRepository.findByClientId(name);
//                optionalUser.ifPresent(user -> validatable.error(new ValidationError(name + " is not available")));
//            } else {
//                validatable.error(new ValidationError(name + " is not invalid"));
//            }
//        }
    }

}

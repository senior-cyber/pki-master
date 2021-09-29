package com.senior.cyber.pki.web.validator;

import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.repository.IntermediateRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.webui.frmk.common.WicketFactory;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.springframework.context.ApplicationContext;

import java.util.Optional;

public class IntermediateOrganizationValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String organization = validatable.getValue();
        if (organization != null && !"".equals(organization)) {
            ApplicationContext context = WicketFactory.getApplicationContext();
            IntermediateRepository intermediateRepository = context.getBean(IntermediateRepository.class);
            UserRepository userRepository = context.getBean(UserRepository.class);
            WebSession session = (WebSession) WebSession.get();
            Optional<User> optionalUser = userRepository.findById(session.getUserId());
            User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
            Optional<Intermediate> optionalIntermediate = intermediateRepository.findByOrganizationAndUserAndStatus(organization, user, "Good");
            optionalIntermediate.ifPresent(root -> validatable.error(new ValidationError(organization + " is not available")));
        }
    }

}

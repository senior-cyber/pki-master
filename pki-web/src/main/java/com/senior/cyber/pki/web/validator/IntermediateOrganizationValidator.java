package com.senior.cyber.pki.web.validator;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.IntermediateStatusEnum;
import com.senior.cyber.pki.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.web.configuration.Mode;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.repository.IntermediateRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
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
            ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
            IntermediateRepository intermediateRepository = context.getBean(IntermediateRepository.class);
            Optional<Intermediate> optionalIntermediate = null;
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                optionalIntermediate = intermediateRepository.findByOrganizationAndStatus(organization, IntermediateStatusEnum.Good);
            } else {
                UserRepository userRepository = context.getBean(UserRepository.class);
                WebSession session = (WebSession) WebSession.get();
                Optional<User> optionalUser = userRepository.findById(session.getUserId());
                User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
                optionalIntermediate = intermediateRepository.findByOrganizationAndUserAndStatus(organization, user, IntermediateStatusEnum.Good);
            }
            optionalIntermediate.ifPresent(root -> validatable.error(new ValidationError(organization + " is not available")));
        }
    }

}

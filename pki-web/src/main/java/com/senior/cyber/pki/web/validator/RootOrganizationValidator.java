package com.senior.cyber.pki.web.validator;

import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.repository.RootRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.webui.frmk.common.WicketFactory;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.springframework.context.ApplicationContext;

import java.util.Optional;

public class RootOrganizationValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String organization = validatable.getValue();
        if (organization != null && !"".equals(organization)) {
            ApplicationContext context = WicketFactory.getApplicationContext();
            RootRepository rootRepository = context.getBean(RootRepository.class);
            UserRepository userRepository = context.getBean(UserRepository.class);
            WebSession session = (WebSession) WebSession.get();
            Optional<User> optionalUser = userRepository.findById(session.getUserId());
            User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
            Optional<Root> optionalRoot = rootRepository.findByOrganizationAndUserAndStatus(organization, user, "Good");
            optionalRoot.ifPresent(root -> validatable.error(new ValidationError(organization + " is not available")));
        }
    }

}

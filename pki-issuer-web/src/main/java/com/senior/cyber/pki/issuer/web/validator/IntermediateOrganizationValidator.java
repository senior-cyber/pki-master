package com.senior.cyber.pki.issuer.web.validator;

import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;

public class IntermediateOrganizationValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String organization = validatable.getValue();
        if (organization != null && !"".equals(organization)) {
            // TODO:
//            ApplicationContext context = WicketFactory.getApplicationContext();
//            ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
//            IntermediateRepository intermediateRepository = context.getBean(IntermediateRepository.class);
//            Optional<Intermediate> optionalIntermediate = null;
//            if (applicationConfiguration.getMode() == Mode.Enterprise) {
//                optionalIntermediate = intermediateRepository.findByOrganizationAndStatus(organization, IntermediateStatusEnum.Good);
//            } else {
//                UserRepository userRepository = context.getBean(UserRepository.class);
//                WebSession session = (WebSession) WebSession.get();
//                Optional<User> optionalUser = userRepository.findById(session.getUserId());
//                User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
//                optionalIntermediate = intermediateRepository.findByOrganizationAndUserAndStatus(organization, user, IntermediateStatusEnum.Good);
//            }
//            optionalIntermediate.ifPresent(root -> validatable.error(new ValidationError(organization + " is not available")));
        }
    }

}

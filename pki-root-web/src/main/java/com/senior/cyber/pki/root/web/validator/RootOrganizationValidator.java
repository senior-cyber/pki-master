package com.senior.cyber.pki.root.web.validator;

//import com.senior.cyber.pki.dao.entity.Root;
//import com.senior.cyber.pki.root.web.repository.RootRepository;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;

public class RootOrganizationValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String organization = validatable.getValue();
//        if (organization != null && !"".equals(organization)) {
//            ApplicationContext context = WicketFactory.getApplicationContext();
//            ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
//            RootRepository rootRepository = context.getBean(RootRepository.class);
//            Optional<Root> optionalRoot = null;
//            if (applicationConfiguration.getMode() == Mode.Enterprise) {
//                optionalRoot = rootRepository.findByOrganizationAndStatus(organization, RootStatusEnum.Good);
//            } else {
//                UserRepository userRepository = context.getBean(UserRepository.class);
//                WebSession session = (WebSession) WebSession.get();
//                Optional<User> optionalUser = userRepository.findById(session.getUserId());
//                User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
//                optionalRoot = rootRepository.findByOrganizationAndUserAndStatus(organization, user, RootStatusEnum.Good);
//            }
//            optionalRoot.ifPresent(root -> validatable.error(new ValidationError(organization + " is not available")));
//        }
    }

}

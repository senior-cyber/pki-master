package com.senior.cyber.pki.root.web.validator;

//import com.senior.cyber.pki.dao.entity.Root;
//import com.senior.cyber.pki.root.web.repository.RootRepository;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;

public class RootCommonNameValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String commonName = validatable.getValue();
//        if (commonName != null && !"".equals(commonName)) {
//            ApplicationContext context = WicketFactory.getApplicationContext();
//            ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
//            RootRepository rootRepository = context.getBean(RootRepository.class);
//            Optional<Root> optionalRoot = null;
//            if (applicationConfiguration.getMode() == Mode.Enterprise) {
//                optionalRoot = rootRepository.findByCommonNameAndStatus(commonName, RootStatusEnum.Good);
//            } else {
//                UserRepository userRepository = context.getBean(UserRepository.class);
//                WebSession session = (WebSession) WebSession.get();
//                Optional<User> optionalUser = userRepository.findById(session.getUserId());
//                User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
//                optionalRoot = rootRepository.findByCommonNameAndUserAndStatus(commonName, user, RootStatusEnum.Good);
//            }
//            optionalRoot.ifPresent(root -> validatable.error(new ValidationError(commonName + " is not available")));
//        }
    }

}

package com.senior.cyber.pki.root.web.validator;

//import com.senior.cyber.pki.dao.entity.Intermediate;
//import com.senior.cyber.pki.root.web.repository.IntermediateRepository;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;

public class IntermediateCommonNameValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String commonName = validatable.getValue();
//        if (commonName != null && !"".equals(commonName)) {
//            ApplicationContext context = WicketFactory.getApplicationContext();
//            ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
//            IntermediateRepository intermediateRepository = context.getBean(IntermediateRepository.class);
//            Optional<Intermediate> optionalIntermediate = null;
//            if (applicationConfiguration.getMode() == Mode.Enterprise) {
//                optionalIntermediate = intermediateRepository.findByCommonNameAndStatus(commonName, IntermediateStatusEnum.Good);
//            } else {
//                UserRepository userRepository = context.getBean(UserRepository.class);
//                WebSession session = (WebSession) WebSession.get();
//                Optional<User> optionalUser = userRepository.findById(session.getUserId());
//                User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
//                optionalIntermediate = intermediateRepository.findByCommonNameAndUserAndStatus(commonName, user, IntermediateStatusEnum.Good);
//            }
//            optionalIntermediate.ifPresent(root -> validatable.error(new ValidationError(commonName + " is not available")));
//        }
    }

}

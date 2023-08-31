package com.senior.cyber.pki.root.web.validator;

import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.root.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.root.web.configuration.Mode;
import com.senior.cyber.pki.root.web.factory.WebSession;
import com.senior.cyber.pki.root.web.factory.WicketFactory;
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
        if (organization != null && !organization.isEmpty()) {
            ApplicationContext context = WicketFactory.getApplicationContext();
            ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
            CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
            UserRepository userRepository = context.getBean(UserRepository.class);
            Optional<Certificate> optionalCertificate = null;
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                optionalCertificate = certificateRepository.findByOrganizationAndStatus(organization, CertificateStatusEnum.Good);
            } else {
                WebSession session = (WebSession) WebSession.get();
                Optional<User> optionalUser = userRepository.findById(session.getUserId());
                User user = optionalUser.orElseThrow(() -> new WicketRuntimeException("Never happen"));
                optionalCertificate = certificateRepository.findByOrganizationAndUserAndStatus(organization, user, CertificateStatusEnum.Good);
            }
            optionalCertificate.ifPresent(certificate -> validatable.error(new ValidationError(organization + " is not available")));
        }
    }

}

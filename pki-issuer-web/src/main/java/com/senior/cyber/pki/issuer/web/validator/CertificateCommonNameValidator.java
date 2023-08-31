package com.senior.cyber.pki.issuer.web.validator;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.issuer.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.issuer.web.configuration.Mode;
import com.senior.cyber.pki.issuer.web.factory.WebSession;
import com.senior.cyber.pki.issuer.web.repository.CertificateRepository;
import com.senior.cyber.pki.issuer.web.repository.UserRepository;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.springframework.context.ApplicationContext;

import java.util.Optional;

public class CertificateCommonNameValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String commonName = validatable.getValue();
        if (commonName != null && !"".equals(commonName)) {
            ApplicationContext context = WicketFactory.getApplicationContext();
            ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
            CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
            Optional<Certificate> optionalCertificate = null;
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                optionalCertificate = certificateRepository.findByCommonNameAndStatus(commonName, CertificateStatusEnum.Good);
            } else {
                UserRepository userRepository = context.getBean(UserRepository.class);
                WebSession session = (WebSession) WebSession.get();
                Optional<User> optionalUser = userRepository.findById(session.getUserId());
                User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
                optionalCertificate = certificateRepository.findByCommonNameAndUserAndStatus(commonName, user, CertificateStatusEnum.Good);
            }
            optionalCertificate.ifPresent(root -> validatable.error(new ValidationError(commonName + " is not available")));
        }
    }

}

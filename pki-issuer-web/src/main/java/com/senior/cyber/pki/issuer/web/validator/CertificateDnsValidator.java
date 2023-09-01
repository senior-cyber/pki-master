package com.senior.cyber.pki.issuer.web.validator;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;

import java.util.ArrayList;
import java.util.List;

public class CertificateDnsValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String[] dnses = StringUtils.split(StringUtils.trimToEmpty(validatable.getValue()), ',');
        DomainValidator validator = DomainValidator.getInstance(true);
        List<String> errors = new ArrayList<>();
        for (String dns : dnses) {
            dns = StringUtils.trimToEmpty(dns);
            if (!"".equals(dns)) {
                if (!validator.isValid(dns)) {
                    errors.add(dns);
                }
            }
        }
        if (!errors.isEmpty()) {
            validatable.error(new ValidationError(StringUtils.join(errors) + " is not valid FQDN"));
        }
    }

}

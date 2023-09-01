package com.senior.cyber.pki.issuer.web.validator;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;

import java.util.ArrayList;
import java.util.List;

public class CertificateIpValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String[] ips = StringUtils.split(StringUtils.trimToEmpty(validatable.getValue()), ',');
        InetAddressValidator validator = InetAddressValidator.getInstance();
        List<String> errors = new ArrayList<>();
        for (String ip : ips) {
            ip = StringUtils.trimToEmpty(ip);
            if (!"".equals(ip)) {
                if (!validator.isValid(ip)) {
                    errors.add(ip);
                }
            }
        }
        if (!errors.isEmpty()) {
            validatable.error(new ValidationError(StringUtils.join(errors) + " is not valid IP"));
        }
    }

}

package com.senior.cyber.pki.root.web.validator;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;

import java.util.ArrayList;
import java.util.List;

public class CertificateSanValidator implements IValidator<String> {

    @Override
    public void validate(IValidatable<String> validatable) {
        String subjectAltNames = StringUtils.trimToEmpty(validatable.getValue());
        List<String> subjectAltName = new ArrayList<>();
        if (subjectAltNames != null && !"".equals(subjectAltNames)) {
            for (String temp : StringUtils.split(subjectAltNames, ",")) {
                temp = StringUtils.trimToEmpty(temp);
                if (!"".equals(temp)) {
                    if (!subjectAltName.contains("IP:" + temp) && !subjectAltName.contains("DNS:" + temp)) {
                        if (InetAddressValidator.getInstance().isValid(temp)) {
                            subjectAltName.add("IP:" + temp);
                        } else if (DomainValidator.getInstance().isValid(temp)) {
                            subjectAltName.add("DNS:" + temp);
                        } else {
                            if (temp.matches("[A-Za-z0-9._-]+")) {
                                subjectAltName.add("DNS:" + temp);
                            } else {
                                if (temp.startsWith("*.")) {
                                    if (DomainValidator.getInstance().isValid(temp.substring(2))) {
                                        subjectAltName.add("DNS:" + temp);
                                    } else {
                                        validatable.error(new ValidationError(temp + " is not valid IP/DNS"));
                                        return;
                                    }
                                } else {
                                    validatable.error(new ValidationError(temp + " is not valid IP/DNS"));
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

}

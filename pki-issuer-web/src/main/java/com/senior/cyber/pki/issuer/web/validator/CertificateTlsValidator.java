package com.senior.cyber.pki.issuer.web.validator;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.FormComponent;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.form.validation.AbstractFormValidator;
import org.apache.wicket.markup.html.form.validation.FormValidatorAdapter;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;

import java.util.ArrayList;
import java.util.List;

public class CertificateTlsValidator extends AbstractFormValidator {

    private TextField<String> ip_field;
    private TextField<String> dns_field;
    private FormComponent<?>[] fields;

    public CertificateTlsValidator(TextField<String> ip_field, TextField<String> dns_field) {
        this.ip_field = ip_field;
        this.dns_field = dns_field;
        this.fields = new FormComponent<?>[]{ip_field, dns_field};
    }

    @Override
    public FormComponent<?>[] getDependentFormComponents() {
        return this.fields;
    }

    @Override
    public void validate(Form<?> form) {
        String ip = this.ip_field.getConvertedInput();
        String dns = this.dns_field.getConvertedInput();
        if ((ip == null || ip.isEmpty()) && (dns == null || dns.isEmpty())) {
            this.ip_field.error(new ValidationError("IP or FQDN is required"));
            this.dns_field.error(new ValidationError("IP or FQDN is required"));
        }
    }

}

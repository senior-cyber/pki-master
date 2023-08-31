package com.senior.cyber.pki.issuer.web.validator;

import com.senior.cyber.frmk.common.wicket.markup.html.form.DateTextField;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.FormComponent;
import org.apache.wicket.markup.html.form.validation.AbstractFormValidator;
import org.apache.wicket.validation.ValidationError;

import java.util.Date;

public class ValidityValidator extends AbstractFormValidator {

    protected final DateTextField valid_from_field;

    protected final DateTextField valid_until_field;

    protected final FormComponent<?>[] components;

    public ValidityValidator(DateTextField valid_from_field, DateTextField valid_until_field) {
        this.valid_from_field = valid_from_field;
        this.valid_until_field = valid_until_field;
        this.components = new FormComponent[]{valid_from_field, valid_until_field};
    }

    @Override
    public FormComponent<?>[] getDependentFormComponents() {
        return this.components;
    }

    @Override
    public void validate(Form<?> form) {
        Date from = valid_from_field.getConvertedInput();
        Date until = valid_until_field.getConvertedInput();
        if (from != null && until != null) {
            if (from.after(until)) {
                valid_from_field.error(new ValidationError("invalid from"));
                valid_until_field.error(new ValidationError("invalid until"));
            }
        }
    }

}

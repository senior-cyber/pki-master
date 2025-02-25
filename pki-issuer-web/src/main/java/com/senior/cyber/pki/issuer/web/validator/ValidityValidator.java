//package com.senior.cyber.pki.issuer.web.validator;
//
//import org.apache.wicket.markup.html.form.Form;
//import org.apache.wicket.markup.html.form.FormComponent;
//import org.apache.wicket.markup.html.form.TextField;
//import org.apache.wicket.markup.html.form.validation.AbstractFormValidator;
//import org.apache.wicket.validation.ValidationError;
//
//import java.text.ParseException;
//import java.text.SimpleDateFormat;
//import java.util.Date;
//
//public class ValidityValidator extends AbstractFormValidator {
//
//    private static final SimpleDateFormat FORMAT = new SimpleDateFormat("dd/MM/yyyy");
//
//    protected final TextField<String> valid_from_field;
//
//    protected final TextField<String> valid_until_field;
//
//    protected final FormComponent<?>[] components;
//
//    public ValidityValidator(TextField<String> valid_from_field, TextField<String> valid_until_field) {
//        this.valid_from_field = valid_from_field;
//        this.valid_until_field = valid_until_field;
//        this.components = new FormComponent[]{valid_from_field, valid_until_field};
//    }
//
//    @Override
//    public FormComponent<?>[] getDependentFormComponents() {
//        return this.components;
//    }
//
//    @Override
//    public void validate(Form<?> form) {
//        try {
//            Date from = FORMAT.parse(valid_from_field.getConvertedInput());
//            Date until = FORMAT.parse(valid_until_field.getConvertedInput());
//            if (from != null && until != null) {
//                if (from.after(until)) {
//                    valid_from_field.error(new ValidationError("invalid from"));
//                    valid_until_field.error(new ValidationError("invalid until"));
//                }
//            }
//        } catch (ParseException e) {
//            valid_from_field.error(new ValidationError("invalid due to " + e.getMessage()));
//        }
//    }
//
//}

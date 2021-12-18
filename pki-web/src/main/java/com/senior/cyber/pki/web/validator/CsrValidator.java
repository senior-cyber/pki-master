package com.senior.cyber.pki.web.validator;

import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;

import java.util.List;

public class CsrValidator implements IValidator<List<FileUpload>> {

    @Override
    public void validate(IValidatable<List<FileUpload>> validatable) {
        List<FileUpload> csrFiles = validatable.getValue();
        if (csrFiles == null || csrFiles.isEmpty()) {
            validatable.error(new ValidationError("csr is required"));
        }
    }

}

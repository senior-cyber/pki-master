package com.senior.cyber.pki.issuer.web.wicket;

import org.apache.wicket.markup.html.form.IChoiceRenderer;

public class OptionChoiceRenderer implements IChoiceRenderer<Option> {

    @Override
    public Object getDisplayValue(Option option) {
        return option.getDisplayValue();
    }

}

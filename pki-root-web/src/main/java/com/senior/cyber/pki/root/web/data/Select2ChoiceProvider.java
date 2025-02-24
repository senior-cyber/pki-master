package com.senior.cyber.pki.root.web.data;

import com.senior.cyber.pki.root.web.factory.WicketFactory;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.AbstractJdbcChoiceProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

public class Select2ChoiceProvider extends AbstractJdbcChoiceProvider {

    public Select2ChoiceProvider(String table, String idField) {
        super(table, idField);
    }

    public Select2ChoiceProvider(String table, String idField, String queryField) {
        super(table, idField, queryField);
    }

    public Select2ChoiceProvider(String table, String idField, String queryField, String orderBy) {
        super(table, idField, queryField, orderBy);
    }

    public Select2ChoiceProvider(String table, String idField, String queryField, String orderBy, String labelField) {
        super(table, idField, queryField, orderBy, labelField);
    }

    @Override
    protected NamedParameterJdbcTemplate getNamedParameterJdbcTemplate() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        return context.getBean(NamedParameterJdbcTemplate.class);
    }
}

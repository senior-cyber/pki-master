package com.senior.cyber.pki.root.web.data;

import com.senior.cyber.pki.root.web.factory.WicketFactory;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.util.AbstractJdbcDataProvider;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.util.Jdbc;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

public class MySqlDataProvider extends AbstractJdbcDataProvider {

    public MySqlDataProvider() {
        super(Jdbc.MySql);
    }

    public MySqlDataProvider(String from) {
        super(Jdbc.MySql, from);
    }

    @Override
    protected NamedParameterJdbcTemplate getNamedParameterJdbcTemplate() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        return context.getBean(NamedParameterJdbcTemplate.class);
    }

}
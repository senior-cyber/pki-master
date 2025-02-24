package com.senior.cyber.pki.issuer.web.data;

import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.util.AbstractJdbcDataProvider;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.util.Jdbc;
import com.senior.cyber.pki.issuer.web.IssuerWebApplication;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
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
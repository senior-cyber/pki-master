package com.senior.cyber.pki.web.data;

import com.senior.cyber.frmk.common.base.WicketFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

public class MySqlDataProvider extends com.senior.cyber.frmk.common.provider.MySqlDataProvider {

    public MySqlDataProvider() {
    }

    public MySqlDataProvider(String from) {
        super(from);
    }

    @Override
    protected NamedParameterJdbcTemplate getNamedParameterJdbcTemplate() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        return context.getBean(NamedParameterJdbcTemplate.class);
    }

}
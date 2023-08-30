package com.senior.cyber.pki.root.web.data;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.Convertor;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Option;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;

public class MultipleChoiceProvider<Id, Label> extends com.senior.cyber.frmk.common.wicket.markup.html.form.select2.MultipleChoiceProvider<Id, Label> {

    public MultipleChoiceProvider(
            Class<Id> idType, Convertor<Id> idConvertor,
            Class<Label> labelType, Convertor<Label> labelConvertor,
            String table, String idField) {
        super(idType, idConvertor, labelType, labelConvertor, table, idField);
    }

    public MultipleChoiceProvider(
            Class<Id> idType, Convertor<Id> idConvertor,
            Class<Label> labelType, Convertor<Label> labelConvertor,
            String table, String idField, String queryField) {
        super(idType, idConvertor, labelType, labelConvertor, table, idField, queryField);
    }

    public MultipleChoiceProvider(
            Class<Id> idType, Convertor<Id> idConvertor,
            Class<Label> labelType, Convertor<Label> labelConvertor,
            String table, String idField, String queryField, String orderBy) {
        super(idType, idConvertor, labelType, labelConvertor, table, idField, queryField, orderBy);
    }

    public MultipleChoiceProvider(
            Class<Id> idType, Convertor<Id> idConvertor,
            Class<Label> labelType, Convertor<Label> labelConvertor,
            String table, String idField, String queryField, String orderBy, String labelField) {
        super(idType, idConvertor, labelType, labelConvertor, table, idField, queryField, orderBy, labelField);
    }

    @Override
    protected Option queryOption(String query, Map<String, Object> params) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        DataSource dataSource = context.getBean(DataSource.class);
        NamedParameterJdbcOperations named = new NamedParameterJdbcTemplate(dataSource);
        List<Option> options = named.query(query, params, (rs, rowNum) -> {
            Id id = rs.getObject("id", idConvertor.getType());
            Label label = rs.getObject("text", labelConvertor.getType());
            return new Option(idConvertor.convertToString(id, null), labelConvertor.convertToString(label, null));
        });
        if (options.isEmpty()) {
            return null;
        } else {
            return options.get(0);
        }
    }

    @Override
    protected List<Option> queryOptions(String query, Map<String, Object> params) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        DataSource dataSource = context.getBean(DataSource.class);
        NamedParameterJdbcOperations named = new NamedParameterJdbcTemplate(dataSource);
        List<Option> options = named.query(query, params, (rs, rowNum) -> {
            Id id = rs.getObject("id", idConvertor.getType());
            Label label = rs.getObject("text", labelConvertor.getType());
            return new Option(idConvertor.convertToString(id, null), labelConvertor.convertToString(label, null));
        });
        return options;
    }
}

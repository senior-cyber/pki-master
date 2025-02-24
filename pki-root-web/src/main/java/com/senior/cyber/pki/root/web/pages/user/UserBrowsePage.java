package com.senior.cyber.pki.root.web.pages.user;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.pki.root.web.factory.WicketFactory;
import com.senior.cyber.frmk.common.jakarta.persistence.Sql;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DefaultDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.IColumn;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.util.AbstractJdbcDataProvider;
import com.senior.cyber.frmk.common.wicket.functional.DeserializerFunction;
import com.senior.cyber.frmk.common.wicket.functional.FilterFunction;
import com.senior.cyber.frmk.common.wicket.functional.SerializerFunction;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.entity.User_;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.root.web.data.MySqlDataProvider;
import com.senior.cyber.pki.root.web.pages.MasterPage;
import jakarta.persistence.Tuple;
import org.apache.commons.lang3.StringUtils;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.model.Model;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Bookmark("/user/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_UserBrowse})
public class UserBrowsePage extends MasterPage {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserBrowsePage.class);

    protected FilterForm user_browse_form;
    protected MySqlDataProvider user_browse_provider;
    protected List<IColumn<Tuple, ? extends Serializable>> user_browse_column;
    protected DataTable<Tuple, Serializable> user_browse_table;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.user_browse_provider = new MySqlDataProvider(Sql.table(User_.class));
        this.user_browse_provider.applyCount(Sql.column(User_.id));
        this.user_browse_provider.applySelect(String.class, "uuid", Sql.column(User_.id));

        this.user_browse_provider.setSort("uuid", SortOrder.DESCENDING);

        this.user_browse_column = new ArrayList<>();
        {
            String label = "Display Name";
            String key = "display_name";
            String sql = Sql.column(User_.displayName);
            SerializerFunction<String> serializer = (value) -> value;
            DeserializerFunction<String> deserializer = (value) -> value;
            FilterFunction<String> filter = (count, alias, params, filterText) -> {
                String v = StringUtils.trimToEmpty(deserializer.apply(filterText));
                if (!v.isEmpty()) {
                    params.put(key, v + "%");
                    return List.of(AbstractJdbcDataProvider.WHERE + sql + " LIKE :" + key);
                } else {
                    return null;
                }
            };
            this.user_browse_column.add(this.user_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Email Address";
            String key = "email_address";
            String sql = Sql.column(User_.emailAddress);
            SerializerFunction<String> serializer = (value) -> value;
            DeserializerFunction<String> deserializer = (value) -> value;
            FilterFunction<String> filter = (count, alias, params, filterText) -> {
                String v = StringUtils.trimToEmpty(deserializer.apply(filterText));
                if (!v.isEmpty()) {
                    params.put(key, v + "%");
                    return List.of(AbstractJdbcDataProvider.WHERE + sql + " LIKE :" + key);
                } else {
                    return null;
                }
            };
            this.user_browse_column.add(this.user_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Enabled";
            String key = "enabled";
            String sql = Sql.column(User_.enabled);
            SerializerFunction<Boolean> serializer = (value) -> {
                if (value == null || !value) {
                    return "No";
                } else {
                    return "Yes";
                }
            };
            this.user_browse_column.add(this.user_browse_provider.column(Boolean.class, Model.of(label), key, sql, serializer));
        }
        this.user_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::user_browse_action_link, this::user_browse_action_click));
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.user_browse_form = new FilterForm("user_browse_form", this.user_browse_provider);
        body.add(this.user_browse_form);

        this.user_browse_table = new DefaultDataTable<>("user_browse_table", this.user_browse_column, this.user_browse_provider, 20);
        this.user_browse_table.addTopToolbar(new FilterToolbar<>(this.user_browse_table, this.user_browse_form));
        this.user_browse_form.add(this.user_browse_table);
    }

    protected List<ActionItem> user_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>(0);
        boolean enabled = model.get("enabled", boolean.class);
        actions.add(new ActionItem("Edit", Model.of("Edit"), ItemCss.SUCCESS));
        if (enabled) {
            actions.add(new ActionItem("Disable", Model.of("Disable"), ItemCss.DANGER));
        } else {
            actions.add(new ActionItem("Enable", Model.of("Enable"), ItemCss.DANGER));
        }
        return actions;
    }

    protected void user_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);

        String uuid = model.get("uuid", String.class);

        if ("Edit".equals(link)) {
            PageParameters parameters = new PageParameters();
            parameters.add("id", uuid);
            setResponsePage(UserModifyPage.class, parameters);
        } else if ("Disable".equals(link)) {
            Optional<User> userOptional = userRepository.findById(uuid);
            User user = userOptional.orElseThrow();
            user.setEnabled(false);
            userRepository.save(user);
            target.add(this.user_browse_table);
        } else if ("Enable".equals(link)) {
            Optional<User> userOptional = userRepository.findById(uuid);
            User user = userOptional.orElseThrow();
            user.setEnabled(true);
            userRepository.save(user);
            target.add(this.user_browse_table);
        }
    }

}

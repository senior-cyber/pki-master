package com.senior.cyber.pki.root.web.pages.role;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.WicketFactory;
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
import com.senior.cyber.pki.dao.entity.Role_;
import com.senior.cyber.pki.dao.repository.RoleRepository;
import com.senior.cyber.pki.root.web.data.MySqlDataProvider;
import com.senior.cyber.pki.root.web.pages.MasterPage;
import jakarta.persistence.Tuple;
import org.apache.commons.lang3.StringUtils;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.model.Model;
import org.springframework.context.ApplicationContext;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Bookmark("/role")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_RoleBrowse})
public class RoleBrowsePage extends MasterPage {

    protected FilterForm role_browse_form;
    protected MySqlDataProvider role_browse_provider;
    protected List<IColumn<Tuple, ? extends Serializable>> role_browse_column;
    protected DataTable<Tuple, Serializable> role_browse_table;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.role_browse_provider = new MySqlDataProvider(Sql.table(Role_.class));
        this.role_browse_provider.setSort("name", SortOrder.ASCENDING);
        this.role_browse_provider.applyCount(Sql.column(Role_.id));

        this.role_browse_provider.applySelect(String.class, "id", Sql.column(Role_.id));

        this.role_browse_column = new ArrayList<>();
        {
            String label = "Name";
            String key = "name";
            String sql = Sql.column(Role_.name);
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
            this.role_browse_column.add(this.role_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Description";
            String key = "description";
            String sql = Sql.column(Role_.description);
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
            this.role_browse_column.add(this.role_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Enabled";
            String key = "enabled";
            String sql = Sql.column(Role_.enabled);
            SerializerFunction<Boolean> serializer = (value) -> {
                if (value == null || !value) {
                    return "No";
                } else {
                    return "Yes";
                }
            };
            this.role_browse_column.add(this.role_browse_provider.column(Boolean.class, Model.of(label), key, sql, serializer));
        }
        this.role_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::role_browse_action_link, this::role_browse_action_click));
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.role_browse_form = new FilterForm("role_browse_form", this.role_browse_provider);
        body.add(this.role_browse_form);

        this.role_browse_table = new DefaultDataTable<>("role_browse_table", this.role_browse_column, this.role_browse_provider, 20);
        this.role_browse_table.addTopToolbar(new FilterToolbar<>(this.role_browse_table, this.role_browse_form));
        this.role_browse_form.add(this.role_browse_table);
    }

    protected List<ActionItem> role_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>(0);
        boolean enabled = model.get("enabled", boolean.class);
        if (enabled) {
            actions.add(new ActionItem("Disable", Model.of("Disable"), ItemCss.DANGER));
        } else {
            actions.add(new ActionItem("Enable", Model.of("Enable"), ItemCss.INFO));
        }
        return actions;
    }

    protected void role_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        RoleRepository roleRepository = context.getBean(RoleRepository.class);
        String uuid = model.get("id", String.class);
        Optional<Role> optionalRole = roleRepository.findById(uuid);
        Role role = optionalRole.orElseThrow();
        if ("Disable".equals(link)) {
            role.setEnabled(false);
            roleRepository.save(role);
            target.add(this.role_browse_table);
        } else if ("Enable".equals(link)) {
            role.setEnabled(true);
            roleRepository.save(role);
            target.add(this.role_browse_table);
        }
    }

}

package com.senior.cyber.pki.root.web.pages.user;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.jakarta.persistence.Sql;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DefaultDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.IColumn;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.util.AbstractJdbcDataProvider;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.functional.DeserializerFunction;
import com.senior.cyber.frmk.common.wicket.functional.FilterFunction;
import com.senior.cyber.frmk.common.wicket.functional.SerializerFunction;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Option;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Select2SingleChoice;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.pki.dao.entity.*;
import com.senior.cyber.pki.dao.repository.RoleRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.root.web.data.MySqlDataProvider;
import com.senior.cyber.pki.root.web.data.Select2ChoiceProvider;
import jakarta.persistence.EntityGraph;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Tuple;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.StringUtils;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.hibernate.jpa.QueryHints;
import org.springframework.context.ApplicationContext;

import java.io.Serializable;
import java.util.*;

public class UserModifyPageDeniedRoleTab extends ContentPanel {

    protected Long uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn role_column;
    protected UIContainer role_container;
    protected Select2SingleChoice role_field;
    protected Select2ChoiceProvider role_provider;
    protected Option role_value;

    protected Button denyButton;
    protected BookmarkablePageLink<Void> cancelButton;

    protected FilterForm role_browse_form;
    protected MySqlDataProvider role_browse_provider;
    protected List<IColumn<Tuple, ? extends Serializable>> role_browse_column;
    protected DataTable<Tuple, Serializable> role_browse_table;

    public UserModifyPageDeniedRoleTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        this.uuid = getPage().getPageParameters().get("id").toLong(-1);

        String not_in = "SELECT " + Sql.column(DenyRole_.roleId) + " FROM " + Sql.table(DenyRole_.class) + " WHERE " + Sql.column(DenyRole_.userId) + " = " + this.uuid;
        this.role_provider = new Select2ChoiceProvider(Sql.table(Role_.class), Sql.column(Role_.id), Sql.column(Role_.name));
        this.role_provider.applyWhere("UserDeny", Sql.column(Role_.id) + " NOT IN (" + not_in + ")");

        this.role_browse_provider = new MySqlDataProvider(Sql.table(Role_.class));
        this.role_browse_provider.applyJoin("UserDeny", "INNER JOIN " + Sql.table(DenyRole_.class) + " ON " + Sql.column(DenyRole_.roleId) + " = " + Sql.column(Role_.id));
        this.role_browse_provider.applyWhere("Group", Sql.column(DenyRole_.userId) + " = :userId", Map.of("userId", this.uuid));
        this.role_browse_provider.setSort("role", SortOrder.ASCENDING);
        this.role_browse_provider.applyCount(Sql.column(DenyRole_.id));
        this.role_browse_provider.applySelect(String.class, "uuid", Sql.column(DenyRole_.id));

        this.role_browse_column = new ArrayList<>();
        {
            String label = "Role";
            String key = "role";
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
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.role_column = this.row1.newUIColumn("role_column", Size.Six_6);
        this.role_container = this.role_column.newUIContainer("role_container");
        this.role_field = new Select2SingleChoice("role_field", new PropertyModel<>(this, "role_value"), this.role_provider);
        this.role_field.setLabel(Model.of("Role"));
        this.role_field.setRequired(true);
        this.role_field.add(new ContainerFeedbackBehavior());
        this.role_container.add(this.role_field);
        this.role_container.newFeedback("role_feedback", this.role_field);

        this.row1.lastUIColumn("last_column");

        this.denyButton = new Button("denyButton") {
            @Override
            public void onSubmit() {
                denyButtonClick();
            }
        };
        this.form.add(this.denyButton);

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", UserBrowsePage.class);
        this.form.add(this.cancelButton);

        this.role_browse_form = new FilterForm("role_browse_form", this.role_browse_provider);
        body.add(this.role_browse_form);

        this.role_browse_table = new DefaultDataTable<>("role_browse_table", this.role_browse_column, this.role_browse_provider, 20);
        this.role_browse_table.addTopToolbar(new FilterToolbar<>(this.role_browse_table, this.role_browse_form));
        this.role_browse_form.add(this.role_browse_table);
    }

    protected List<ActionItem> role_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>();
        actions.add(new ActionItem("Remove", Model.of("Remove"), ItemCss.DANGER));
        return actions;
    }

    protected void role_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        if ("Remove".equals(link)) {
            String uuid = model.get("uuid", String.class);
            ApplicationContext context = WicketFactory.getApplicationContext();
            UserRepository userRepository = context.getBean(UserRepository.class);
            EntityManager entityManager = context.getBean(EntityManager.class);
            CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
            CriteriaQuery<User> criteriaQuery = criteriaBuilder.createQuery(User.class);

            EntityGraph<User> graph = entityManager.createEntityGraph(User.class);
            graph.addAttributeNodes(User_.denyRoles);

            Root<User> root = criteriaQuery.from(User.class);
            criteriaQuery.select(root);
            criteriaQuery.where(criteriaBuilder.equal(root.get(User_.id), this.uuid));
            TypedQuery<User> query = entityManager.createQuery(criteriaQuery);
            query.setHint(QueryHints.HINT_LOADGRAPH, graph);
            User user = query.getSingleResult();

            user.getDenyRoles().remove(uuid);
            userRepository.save(user);
            target.add(this.role_browse_table);
        }
    }

    protected void denyButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        RoleRepository roleRepository = context.getBean(RoleRepository.class);
        UserRepository userRepository = context.getBean(UserRepository.class);
        EntityManager entityManager = context.getBean(EntityManager.class);
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> criteriaQuery = criteriaBuilder.createQuery(User.class);

        EntityGraph<User> graph = entityManager.createEntityGraph(User.class);
        graph.addAttributeNodes(User_.denyRoles);

        Root<User> root = criteriaQuery.from(User.class);
        criteriaQuery.select(root);
        criteriaQuery.where(criteriaBuilder.equal(root.get(User_.id), this.uuid));
        TypedQuery<User> query = entityManager.createQuery(criteriaQuery);
        query.setHint(QueryHints.HINT_LOADGRAPH, graph);
        User user = query.getSingleResult();

        Role role = roleRepository.findById(this.role_value.getId()).orElseThrow();
        if (user.getDenyRoles() == null || user.getDenyRoles().isEmpty()) {
            Map<String, Role> roles = new HashMap<>();
            roles.put(UUID.randomUUID().toString(), role);
            user.setDenyRoles(roles);
        } else {
            user.getDenyRoles().put(UUID.randomUUID().toString(), role);
        }
        userRepository.save(user);
    }

}

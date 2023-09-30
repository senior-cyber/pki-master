package com.senior.cyber.pki.issuer.web.pages.user;

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
import com.senior.cyber.pki.dao.repository.GroupRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.data.MySqlDataProvider;
import com.senior.cyber.pki.issuer.web.data.Select2ChoiceProvider;
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

public class UserModifyPageGroupTab extends ContentPanel {

    protected Long uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn group_column;
    protected UIContainer group_container;
    protected Select2SingleChoice group_field;
    protected Select2ChoiceProvider group_provider;
    protected Option group_value;

    protected Button addButton;
    protected BookmarkablePageLink<Void> cancelButton;

    protected FilterForm group_browse_form;
    protected MySqlDataProvider group_browse_provider;
    protected List<IColumn<Tuple, ? extends Serializable>> group_browse_column;
    protected DataTable<Tuple, Serializable> group_browse_table;

    public UserModifyPageGroupTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        this.uuid = getPage().getPageParameters().get("id").toLong(-1);

        String not_in = "SELECT " + Sql.column(UserGroup_.groupId) + " FROM " + Sql.table(UserGroup_.class) + " WHERE " + Sql.column(UserGroup_.userId) + " = " + this.uuid;
        this.group_provider = new Select2ChoiceProvider(Sql.table(Group_.class), Sql.column(Group_.id), Sql.column(Group_.name));
        this.group_provider.applyWhere("GroupRole", Sql.column(Group_.id) + " NOT IN (" + not_in + ")");

        this.group_browse_provider = new MySqlDataProvider(Sql.table(Group_.class));
        this.group_browse_provider.applyJoin("UserGroup", "INNER JOIN " + Sql.table(UserGroup_.class) + " ON " + Sql.column(UserGroup_.groupId) + " = " + Sql.column(Group_.id));
        this.group_browse_provider.applyWhere("User", Sql.column(UserGroup_.userId) + " = " + this.uuid);
        this.group_browse_provider.setSort("group_name", SortOrder.ASCENDING);
        this.group_browse_provider.applyCount(Sql.column(UserGroup_.id));
        this.group_browse_provider.applySelect(String.class, "uuid", Sql.column(UserGroup_.id));

        this.group_browse_column = new ArrayList<>();
        {
            String label = "Name";
            String key = "group_name";
            String sql = Sql.column(Group_.name);
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
            this.group_browse_column.add(this.group_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Enabled";
            String key = "enabled";
            String sql = Sql.column(Group_.enabled);
            SerializerFunction<Boolean> serializer = (value) -> {
                if (value == null || !value) {
                    return "No";
                } else {
                    return "Yes";
                }
            };
            this.group_browse_column.add(this.group_browse_provider.column(Boolean.class, Model.of(label), key, sql, serializer));
        }
        this.group_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::group_browse_action_link, this::group_browse_action_click));
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.group_column = this.row1.newUIColumn("group_column", Size.Six_6);
        this.group_container = this.group_column.newUIContainer("group_container");
        this.group_field = new Select2SingleChoice("group_field", new PropertyModel<>(this, "group_value"), this.group_provider);
        this.group_field.setLabel(Model.of("Group"));
        this.group_field.setRequired(true);
        this.group_field.add(new ContainerFeedbackBehavior());
        this.group_container.add(this.group_field);
        this.group_container.newFeedback("group_feedback", this.group_field);

        this.row1.lastUIColumn("last_column");

        this.addButton = new Button("addButton") {
            @Override
            public void onSubmit() {
                addButtonClick();
            }
        };
        this.form.add(this.addButton);

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", UserBrowsePage.class);
        this.form.add(this.cancelButton);

        this.group_browse_form = new FilterForm("group_browse_form", this.group_browse_provider);
        body.add(this.group_browse_form);

        this.group_browse_table = new DefaultDataTable<>("group_browse_table", this.group_browse_column, this.group_browse_provider, 20);
        this.group_browse_table.addTopToolbar(new FilterToolbar<>(this.group_browse_table, this.group_browse_form));
        this.group_browse_form.add(this.group_browse_table);
    }

    protected List<ActionItem> group_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>();
        actions.add(new ActionItem("Remove", Model.of("Remove"), ItemCss.DANGER));
        return actions;
    }

    protected void group_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        if ("Remove".equals(link)) {
            String uuid = model.get("uuid", String.class);

            ApplicationContext context = WicketFactory.getApplicationContext();
            UserRepository userRepository = context.getBean(UserRepository.class);
            EntityManager entityManager = context.getBean(EntityManager.class);
            CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
            CriteriaQuery<User> criteriaQuery = criteriaBuilder.createQuery(User.class);

            EntityGraph<User> graph = entityManager.createEntityGraph(User.class);
            graph.addAttributeNodes(User_.groups);

            Root<User> root = criteriaQuery.from(User.class);
            criteriaQuery.select(root);
            criteriaQuery.where(criteriaBuilder.equal(root.get(User_.id), this.uuid));
            TypedQuery<User> query = entityManager.createQuery(criteriaQuery);
            query.setHint(QueryHints.HINT_LOADGRAPH, graph);
            User user = query.getSingleResult();

            user.getGroups().remove(uuid);
            userRepository.save(user);
            target.add(this.group_browse_table);
        }
    }

    protected void addButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        GroupRepository groupRepository = context.getBean(GroupRepository.class);
        EntityManager entityManager = context.getBean(EntityManager.class);
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> criteriaQuery = criteriaBuilder.createQuery(User.class);

        EntityGraph<User> graph = entityManager.createEntityGraph(User.class);
        graph.addAttributeNodes(User_.groups);

        Root<User> root = criteriaQuery.from(User.class);
        criteriaQuery.select(root);
        criteriaQuery.where(criteriaBuilder.equal(root.get(User_.id), this.uuid));
        TypedQuery<User> query = entityManager.createQuery(criteriaQuery);
        query.setHint(QueryHints.HINT_LOADGRAPH, graph);
        User user = query.getSingleResult();

        Group group = groupRepository.findById(this.group_value.getId()).orElseThrow();
        if (user.getGroups() == null || user.getGroups().isEmpty()) {
            Map<String, Group> groups = new HashMap<>();
            groups.put(UUID.randomUUID().toString(), group);
            user.setGroups(groups);
        } else {
            user.getGroups().put(UUID.randomUUID().toString(), group);
        }
        userRepository.save(user);
    }

}

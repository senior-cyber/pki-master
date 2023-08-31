package com.senior.cyber.pki.root.web.pages.group;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.jpa.Sql;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
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
import com.senior.cyber.pki.root.web.data.MySqlDataProvider;
import com.senior.cyber.pki.root.web.data.SingleChoiceProvider;
import jakarta.persistence.EntityGraph;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Tuple;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.extensions.markup.html.repeater.data.table.IColumn;
import org.apache.wicket.extensions.markup.html.repeater.data.table.filter.FilterForm;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.hibernate.jpa.QueryHints;
import org.springframework.context.ApplicationContext;

import java.util.*;

public class GroupModifyPageMemberTab extends ContentPanel {

    protected Long uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn user_column;
    protected UIContainer user_container;
    protected Select2SingleChoice user_field;
    protected SingleChoiceProvider<String, String> user_provider;
    protected Option user_value;

    protected Button addButton;
    protected BookmarkablePageLink<Void> cancelButton;

    protected FilterForm<Map<String, Expression<?>>> user_browse_form;
    protected MySqlDataProvider user_browse_provider;
    protected List<IColumn<Tuple, String>> user_browse_column;
    protected AbstractDataTable<Tuple, String> user_browse_table;

    public GroupModifyPageMemberTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        this.uuid = getPage().getPageParameters().get("id").toLong(-1);

        String not_in = "SELECT " + Sql.column(UserGroup_.userId) + " FROM " + Sql.table(UserGroup_.class) + " WHERE " + Sql.column(UserGroup_.groupId) + " = " + this.uuid;
        this.user_provider = new SingleChoiceProvider<>(
                String.class, new StringConvertor(),
                String.class, new StringConvertor(),
                Sql.table(User_.class), Sql.column(User_.id),
                Sql.column(User_.displayName));
        this.user_provider.applyWhere("UserGroup", Sql.column(User_.id) + " NOT IN (" + not_in + ")");

        this.user_browse_provider = new MySqlDataProvider(Sql.table(User_.class));
        this.user_browse_provider.applyJoin("UserGroup", "INNER JOIN " + Sql.table(UserGroup_.class) + " ON " + Sql.column(UserGroup_.userId) + " = " + Sql.column(User_.id));
        this.user_browse_provider.applyWhere("Group", Sql.column(UserGroup_.groupId) + " = " + this.uuid);
        this.user_browse_provider.setSort("full_name", SortOrder.ASCENDING);
        this.user_browse_provider.setCountField(Sql.column(UserGroup_.id));
        this.user_browse_provider.selectNormalColumn("uuid", Sql.column(UserGroup_.id), new StringConvertor());

        this.user_browse_column = new ArrayList<>();
        this.user_browse_column.add(Column.normalColumn(Model.of("Name"), "full_name", Sql.column(User_.displayName), this.user_browse_provider, new StringConvertor()));
        this.user_browse_column.add(Column.normalColumn(Model.of("Login"), "login", Sql.column(User_.login), this.user_browse_provider, new StringConvertor()));
        this.user_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::user_browse_action_link, this::user_browse_action_click));
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.user_column = this.row1.newUIColumn("user_column", Size.Six_6);
        this.user_container = this.user_column.newUIContainer("user_container");
        this.user_field = new Select2SingleChoice("user_field", new PropertyModel<>(this, "user_value"),
                this.user_provider);
        this.user_field.setLabel(Model.of("User"));
        this.user_field.setRequired(true);
        this.user_field.add(new ContainerFeedbackBehavior());
        this.user_container.add(this.user_field);
        this.user_container.newFeedback("user_feedback", this.user_field);

        this.row1.lastUIColumn("last_column");

        this.addButton = new Button("addButton") {
            @Override
            public void onSubmit() {
                addButtonClick();
            }
        };
        this.form.add(this.addButton);

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", GroupBrowsePage.class);
        this.form.add(this.cancelButton);

        this.user_browse_form = new FilterForm<>("user_browse_form", this.user_browse_provider);
        body.add(this.user_browse_form);

        this.user_browse_table = new DataTable<>("user_browse_table", this.user_browse_column, this.user_browse_provider, 20);
        this.user_browse_form.add(this.user_browse_table);
    }

    protected List<ActionItem> user_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>();
        actions.add(new ActionItem("Remove", Model.of("Remove"), ItemCss.DANGER));
        return actions;
    }

    protected void user_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        if ("Remove".equals(link)) {
            String uuid = model.get("uuid", String.class);
            ApplicationContext context = WicketFactory.getApplicationContext();
            GroupRepository groupRepository = context.getBean(GroupRepository.class);
            EntityManager entityManager = context.getBean(EntityManager.class);
            CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
            CriteriaQuery<Group> criteriaQuery = criteriaBuilder.createQuery(Group.class);

            EntityGraph<Group> graph = entityManager.createEntityGraph(Group.class);
            graph.addAttributeNodes(Group_.users);

            Root<Group> root = criteriaQuery.from(Group.class);
            criteriaQuery.select(root);
            criteriaQuery.where(criteriaBuilder.equal(root.get(Group_.id), this.uuid));
            TypedQuery<Group> query = entityManager.createQuery(criteriaQuery);
            query.setHint(QueryHints.HINT_LOADGRAPH, graph);
            Group group = query.getSingleResult();

            group.getUsers().remove(uuid);

            groupRepository.save(group);

            target.add(this.user_browse_table);
        }
    }

    protected void addButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        GroupRepository groupRepository = context.getBean(GroupRepository.class);
        EntityManager entityManager = context.getBean(EntityManager.class);
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Group> criteriaQuery = criteriaBuilder.createQuery(Group.class);

        EntityGraph<Group> graph = entityManager.createEntityGraph(Group.class);
        graph.addAttributeNodes(Group_.users);

        Root<Group> root = criteriaQuery.from(Group.class);
        criteriaQuery.select(root);
        criteriaQuery.where(criteriaBuilder.equal(root.get(Group_.id), this.uuid));
        TypedQuery<Group> query = entityManager.createQuery(criteriaQuery);
        query.setHint(QueryHints.HINT_LOADGRAPH, graph);
        Group group = query.getSingleResult();

        User user = userRepository.findById(this.user_value.getId()).orElseThrow();
        if (group.getUsers() == null || group.getUsers().isEmpty()) {
            Map<String, User> users = new HashMap<>();
            users.put(UUID.randomUUID().toString(), user);
            group.setUsers(users);
        } else {
            group.getUsers().put(UUID.randomUUID().toString(), user);
        }
        groupRepository.save(group);
    }

}

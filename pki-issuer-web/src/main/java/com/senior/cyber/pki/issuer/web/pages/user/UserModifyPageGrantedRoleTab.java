package com.senior.cyber.pki.issuer.web.pages.user;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.jpa.Sql;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.BooleanConvertor;
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
import com.senior.cyber.pki.dao.repository.RoleRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.data.MySqlDataProvider;
import com.senior.cyber.pki.issuer.web.data.SingleChoiceProvider;
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

public class UserModifyPageGrantedRoleTab extends ContentPanel {

    protected Long uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn role_column;
    protected UIContainer role_container;
    protected Select2SingleChoice role_field;
    protected SingleChoiceProvider<String, String> role_provider;
    protected Option role_value;

    protected Button grantButton;
    protected BookmarkablePageLink<Void> cancelButton;

    protected FilterForm<Map<String, Expression<?>>> role_browse_form;
    protected MySqlDataProvider role_browse_provider;
    protected List<IColumn<Tuple, String>> role_browse_column;
    protected AbstractDataTable<Tuple, String> role_browse_table;

    public UserModifyPageGrantedRoleTab(String id, String name, TabbedPanel<Tab> containerPanel,
                                        Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        this.uuid = getPage().getPageParameters().get("id").toLong(-1);

        String not_in = "SELECT " + Sql.column(UserRole_.roleId) + " FROM " + Sql.table(UserRole_.class) + " WHERE " + Sql.column(UserRole_.userId) + " = " + this.uuid;
        this.role_provider = new SingleChoiceProvider<>(String.class, new StringConvertor(),
                String.class, new StringConvertor(),
                Sql.table(Role_.class), Sql.column(Role_.id), Sql.column(Role_.name));
        this.role_provider.applyWhere("UserRole", Sql.column(Role_.id) + " NOT IN (" + not_in + ")");

        this.role_browse_provider = new MySqlDataProvider(Sql.table(Role_.class));
        this.role_browse_provider.applyJoin("UserRole", "INNER JOIN " + Sql.table(UserRole_.class) + " ON " + Sql.column(UserRole_.roleId) + " = " + Sql.column(Role_.id));
        this.role_browse_provider.applyWhere("Group", Sql.column(UserRole_.userId) + " = " + this.uuid);
        this.role_browse_provider.setSort("role", SortOrder.ASCENDING);
        this.role_browse_provider.setCountField(Sql.column(UserRole_.id));
        this.role_browse_provider.selectNormalColumn("uuid", Sql.column(UserRole_.id), new StringConvertor());

        this.role_browse_column = new ArrayList<>();
        this.role_browse_column.add(Column.normalColumn(Model.of("Role"), "role", Sql.column(Role_.name), this.role_browse_provider, new StringConvertor()));
        this.role_browse_column.add(Column.normalColumn(Model.of("Description"), "description", Sql.column(Role_.description), this.role_browse_provider, new StringConvertor()));
        this.role_browse_column.add(Column.normalColumn(Model.of("Enabled"), "enabled", Sql.column(Role_.enabled), this.role_browse_provider, new BooleanConvertor()));
        this.role_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::role_browse_action_link, this::role_browse_action_click));
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.role_column = this.row1.newUIColumn("role_column", Size.Six_6);
        this.role_container = this.role_column.newUIContainer("role_container");
        this.role_field = new Select2SingleChoice("role_field", new PropertyModel<>(this, "role_value"),
                this.role_provider);
        this.role_field.setLabel(Model.of("Role"));
        this.role_field.setRequired(true);
        this.role_field.add(new ContainerFeedbackBehavior());
        this.role_container.add(this.role_field);
        this.role_container.newFeedback("role_feedback", this.role_field);

        this.row1.lastUIColumn("last_column");

        this.grantButton = new Button("grantButton") {
            @Override
            public void onSubmit() {
                grantButtonClick();
            }
        };
        this.form.add(this.grantButton);

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", UserBrowsePage.class);
        this.form.add(this.cancelButton);

        this.role_browse_form = new FilterForm<>("role_browse_form", this.role_browse_provider);
        body.add(this.role_browse_form);

        this.role_browse_table = new DataTable<>("role_browse_table", this.role_browse_column,
                this.role_browse_provider, 20);
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
            graph.addAttributeNodes(User_.roles);

            Root<User> root = criteriaQuery.from(User.class);
            criteriaQuery.select(root);
            criteriaQuery.where(criteriaBuilder.equal(root.get(User_.id), this.uuid));
            TypedQuery<User> query = entityManager.createQuery(criteriaQuery);
            query.setHint(QueryHints.HINT_LOADGRAPH, graph);
            User user = query.getSingleResult();

            user.getRoles().remove(uuid);
            userRepository.save(user);
            target.add(this.role_browse_table);
        }
    }

    protected void grantButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        RoleRepository roleRepository = context.getBean(RoleRepository.class);
        UserRepository userRepository = context.getBean(UserRepository.class);
        EntityManager entityManager = context.getBean(EntityManager.class);
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> criteriaQuery = criteriaBuilder.createQuery(User.class);

        EntityGraph<User> graph = entityManager.createEntityGraph(User.class);
        graph.addAttributeNodes(User_.roles);

        Root<User> root = criteriaQuery.from(User.class);
        criteriaQuery.select(root);
        criteriaQuery.where(criteriaBuilder.equal(root.get(User_.id), this.uuid));
        TypedQuery<User> query = entityManager.createQuery(criteriaQuery);
        query.setHint(QueryHints.HINT_LOADGRAPH, graph);
        User user = query.getSingleResult();

        Role role = roleRepository.findById(this.role_value.getId()).orElseThrow();
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            Map<String, Role> roles = new HashMap<>();
            roles.put(UUID.randomUUID().toString(), role);
            user.setRoles(roles);
        } else {
            user.getRoles().put(UUID.randomUUID().toString(), role);
        }
        userRepository.save(user);
    }

}

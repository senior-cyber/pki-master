package com.senior.cyber.pki.web.pages.user;

import com.senior.cyber.pki.dao.entity.Group;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.entity.User_;
import com.senior.cyber.pki.web.data.MySqlDataProvider;
import com.senior.cyber.pki.web.data.SingleChoiceProvider;
import com.senior.cyber.pki.web.repository.GroupRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.webui.frmk.common.WicketFactory;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.convertor.BooleanConvertor;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.webui.frmk.wicket.layout.Size;
import com.senior.cyber.webui.frmk.wicket.layout.UIColumn;
import com.senior.cyber.webui.frmk.wicket.layout.UIContainer;
import com.senior.cyber.webui.frmk.wicket.layout.UIRow;
import com.senior.cyber.webui.frmk.wicket.markup.html.form.select2.Option;
import com.senior.cyber.webui.frmk.wicket.markup.html.form.select2.Select2SingleChoice;
import com.senior.cyber.webui.frmk.wicket.markup.html.panel.ContainerFeedbackBehavior;
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

import javax.persistence.EntityGraph;
import javax.persistence.EntityManager;
import javax.persistence.Tuple;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.util.*;

public class UserModifyPageGroupTab extends ContentPanel {

    protected Long uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn group_column;
    protected UIContainer group_container;
    protected Select2SingleChoice group_field;
    protected SingleChoiceProvider<Long, String> group_provider;
    protected Option group_value;

    protected Button addButton;
    protected BookmarkablePageLink<Void> cancelButton;

    protected FilterForm<Map<String, Expression<?>>> group_browse_form;
    protected MySqlDataProvider group_browse_provider;
    protected List<IColumn<Tuple, String>> group_browse_column;
    protected AbstractDataTable<Tuple, String> group_browse_table;

    public UserModifyPageGroupTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        this.uuid = getPage().getPageParameters().get("id").toLong(-1);

        String not_in = "SELECT ug.r_group_id FROM tbl_user_group ug WHERE ug.r_user_id = " + this.uuid;
        this.group_provider = new SingleChoiceProvider<>(Long.class, new LongConvertor(), String.class, new StringConvertor(), "tbl_group g", "g.group_id", "g.name");
        this.group_provider.applyWhere("GroupRole", "g.group_id NOT IN (" + not_in + ")");

        this.group_browse_provider = new MySqlDataProvider("tbl_group g");
        this.group_browse_provider.applyJoin("UserGroup", "INNER JOIN tbl_user_group ug ON ug.r_group_id = g.group_id");
        this.group_browse_provider.applyWhere("User", "ug.r_user_id = " + this.uuid);
        this.group_browse_provider.setSort("group_name", SortOrder.ASCENDING);
        this.group_browse_provider.setCountField("ug.user_group_id");
        this.group_browse_provider.selectNormalColumn("uuid", "ug.user_group_id", new StringConvertor());

        this.group_browse_column = new ArrayList<>();
        this.group_browse_column.add(Column.normalColumn(Model.of("Group"), "group_name", "g.name", this.group_browse_provider, new StringConvertor()));
        this.group_browse_column.add(Column.normalColumn(Model.of("Enabled"), "enabled", "g.enabled", this.group_browse_provider, new BooleanConvertor()));
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

        this.group_browse_form = new FilterForm<>("group_browse_form", this.group_browse_provider);
        body.add(this.group_browse_form);

        this.group_browse_table = new DataTable<>("group_browse_table", this.group_browse_column, this.group_browse_provider, 20);
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
            graph.addAttributeNodes("groups");

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
        graph.addAttributeNodes("groups");

        Root<User> root = criteriaQuery.from(User.class);
        criteriaQuery.select(root);
        criteriaQuery.where(criteriaBuilder.equal(root.get(User_.id), this.uuid));
        TypedQuery<User> query = entityManager.createQuery(criteriaQuery);
        query.setHint(QueryHints.HINT_LOADGRAPH, graph);
        User user = query.getSingleResult();

        Group group = groupRepository.findById(Long.valueOf(this.group_value.getId())).orElseThrow();
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

package com.senior.cyber.pki.web.pages.user;

import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.Session;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.data.MySqlDataProvider;
import com.senior.cyber.pki.web.pages.MasterPage;
import com.senior.cyber.pki.web.repository.HSessionRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.webui.frmk.common.Bookmark;
import com.senior.cyber.webui.frmk.common.WicketFactory;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.convertor.BooleanConvertor;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.extensions.markup.html.repeater.data.table.IColumn;
import org.apache.wicket.extensions.markup.html.repeater.data.table.filter.FilterForm;
import org.apache.wicket.model.Model;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import javax.persistence.Tuple;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Bookmark("/user/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_UserBrowse})
public class UserBrowsePage extends MasterPage {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserBrowsePage.class);

    protected FilterForm<Map<String, Expression<?>>> user_browse_form;
    protected MySqlDataProvider user_browse_provider;
    protected List<IColumn<Tuple, String>> user_browse_column;
    protected AbstractDataTable<Tuple, String> user_browse_table;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.user_browse_provider = new MySqlDataProvider("tbl_user u");
        this.user_browse_provider.setCountField("u.user_id");

        this.user_browse_provider.selectNormalColumn("uuid", "u.user_id", new LongConvertor());

        this.user_browse_provider.setSort("uuid", SortOrder.DESCENDING);

        this.user_browse_column = new ArrayList<>();
        this.user_browse_column.add(FilteredColumn.normalColumn(Model.of("Display Name"), "display_name", "u.display_name", this.user_browse_provider, new StringConvertor()));
        this.user_browse_column.add(FilteredColumn.normalColumn(Model.of("Email Address"), "email_address", "u.email_address", this.user_browse_provider, new StringConvertor()));
        this.user_browse_column.add(FilteredColumn.normalColumn(Model.of("Enabled"), "enabled", "u.enabled", this.user_browse_provider, new BooleanConvertor()));
        this.user_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::user_browse_action_link, this::user_browse_action_click));
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.user_browse_form = new FilterForm<>("user_browse_form", this.user_browse_provider);
        body.add(this.user_browse_form);

        this.user_browse_table = new DataTable<>("user_browse_table", this.user_browse_column,
                this.user_browse_provider, 20);
        this.user_browse_table.addTopToolbar(new FilterToolbar(this.user_browse_table, this.user_browse_form));
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

        long uuid = model.get("uuid", Long.class);

        if ("Edit".equals(link)) {
            PageParameters parameters = new PageParameters();
            parameters.add("id", uuid);
            setResponsePage(UserModifyPage.class, parameters);
        } else if ("Disable".equals(link)) {
            Optional<User> userOptional = userRepository.findById(uuid);
            User user = userOptional.orElseThrow();
            user.setEnabled(false);
            userRepository.save(user);

            HSessionRepository sessionRepository = context.getBean(HSessionRepository.class);
            List<Session> sessions = sessionRepository.findByLogin(user.getLogin());
            for (Session session : sessions) {
                sessionRepository.delete(session);
            }

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

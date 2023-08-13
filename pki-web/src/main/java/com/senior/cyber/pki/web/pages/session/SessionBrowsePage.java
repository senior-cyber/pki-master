package com.senior.cyber.pki.web.pages.session;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.Permission;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import com.senior.cyber.frmk.jdbc.query.DeleteQuery;
import com.senior.cyber.frmk.jdbc.query.Param;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.web.configuration.Mode;
import com.senior.cyber.pki.web.data.MySqlDataProvider;
import com.senior.cyber.pki.web.pages.MasterPage;
import jakarta.persistence.Tuple;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.extensions.markup.html.repeater.data.table.IColumn;
import org.apache.wicket.extensions.markup.html.repeater.data.table.filter.FilterForm;
import org.apache.wicket.model.Model;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Bookmark("/session/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_SessionBrowse})
public class SessionBrowsePage extends MasterPage {

    protected FilterForm<Map<String, Expression<?>>> session_browse_form;
    protected MySqlDataProvider session_browse_provider;
    protected List<IColumn<Tuple, String>> session_browse_column;
    protected AbstractDataTable<Tuple, String> session_browse_table;

    @Override
    protected void onInitData() {
        super.onInitData();

        this.session_browse_provider = new MySqlDataProvider("TBL_SESSION sp");
        this.session_browse_provider.setSort("sp.SESSION_ID", SortOrder.DESCENDING);
        this.session_browse_provider.setCountField("sp.SESSION_ID");
        this.session_browse_provider.selectNormalColumn("uuid", "sp.PRIMARY_ID", new StringConvertor());

        this.session_browse_column = new ArrayList<>();
        this.session_browse_column.add(Column.normalColumn(Model.of("Session ID"), "sessionId", "sp.SESSION_ID", this.session_browse_provider, new StringConvertor()));
        this.session_browse_column.add(Column.normalColumn(Model.of("Login"), "login", "sp.login", this.session_browse_provider, new StringConvertor()));
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_SessionBrowse_Revoke_Action)) {
                this.session_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::session_browse_action_link, this::session_browse_action_click));
            }
        } else {
            this.session_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::session_browse_action_link, this::session_browse_action_click));
        }
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.session_browse_form = new FilterForm<>("session_browse_form", this.session_browse_provider);
        body.add(this.session_browse_form);

        this.session_browse_table = new DataTable<>("session_browse_table", this.session_browse_column, this.session_browse_provider, 20);
        this.session_browse_form.add(this.session_browse_table);
    }

    protected List<ActionItem> session_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>(0);
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_SessionBrowse_Revoke_Action)) {
                actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.INFO));
            }
        } else {
            actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.INFO));
        }
        return actions;
    }

    protected void session_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if ("Revoke".equals(link)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                Permission.tryAccess(getSession(), Role.NAME_ROOT, Role.NAME_Page_SessionBrowse_Revoke_Action);
            }
            String uuid = model.get("uuid", String.class);
            NamedParameterJdbcTemplate named = context.getBean(NamedParameterJdbcTemplate.class);
            DeleteQuery deleteQuery = null;

            deleteQuery = new DeleteQuery("TBL_SESSION_ATTRIBUTES");
            deleteQuery.addWhere("SESSION_PRIMARY_ID = :SESSION_PRIMARY_ID", new Param("SESSION_PRIMARY_ID", uuid));
            named.update(deleteQuery.toSQL(), deleteQuery.toParam());

            deleteQuery = new DeleteQuery("TBL_SESSION");
            deleteQuery.addWhere("PRIMARY_ID = :PRIMARY_ID", new Param("PRIMARY_ID", uuid));
            named.update(deleteQuery.toSQL(), deleteQuery.toParam());

            target.add(this.session_browse_table);

            String sessionId = model.get("sessionId", String.class);
            HttpServletRequest request = (HttpServletRequest) getRequest().getContainerRequest();
            String currentSessionId = request.getSession(true).getId();
            if (currentSessionId.equals(sessionId)) {
                setResponsePage(getApplication().getHomePage());
            }
        }
    }

}

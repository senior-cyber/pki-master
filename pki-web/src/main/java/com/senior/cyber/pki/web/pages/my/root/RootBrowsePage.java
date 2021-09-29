package com.senior.cyber.pki.web.pages.my.root;

import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.web.data.MySqlDataProvider;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.pages.MasterPage;
import com.senior.cyber.webui.frmk.common.Bookmark;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.extensions.markup.html.repeater.data.table.IColumn;
import org.apache.wicket.extensions.markup.html.repeater.data.table.filter.FilterForm;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.request.mapper.parameter.PageParameters;

import javax.persistence.Tuple;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Bookmark("/my/root/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyRootBrowse})
public class RootBrowsePage extends MasterPage {

    protected FilterForm<Map<String, Expression<?>>> root_browse_form;
    protected MySqlDataProvider root_browse_provider;
    protected List<IColumn<Tuple, String>> root_browse_column;
    protected AbstractDataTable<Tuple, String> root_browse_table;

    protected BookmarkablePageLink<Void> createButton;

    @Override
    protected void onInitData() {
        super.onInitData();
        WebSession session = getSession();
        this.root_browse_provider = new MySqlDataProvider("tbl_root");
        this.root_browse_provider.setSort("root_id", SortOrder.DESCENDING);
        this.root_browse_provider.applyWhere("user", "user_id = " + session.getUserId());
        this.root_browse_provider.setCountField("root_id");

        this.root_browse_column = new ArrayList<>();
        this.root_browse_column.add(Column.normalColumn(Model.of("ID"), "uuid", "root_id", this.root_browse_provider, new LongConvertor()));
        this.root_browse_column.add(Column.normalColumn(Model.of("Name"), "common_name", "common_name", this.root_browse_provider, new StringConvertor()));
        this.root_browse_column.add(Column.normalColumn(Model.of("Status"), "status", "status", this.root_browse_provider, new StringConvertor()));
        this.root_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::root_browse_action_link, this::root_browse_action_click));
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.root_browse_form = new FilterForm<>("root_browse_form", this.root_browse_provider);
        body.add(this.root_browse_form);

        this.root_browse_table = new DataTable<>("root_browse_table", this.root_browse_column,
                this.root_browse_provider, 20);
        this.root_browse_form.add(this.root_browse_table);

        this.createButton = new BookmarkablePageLink<>("createButton", RootGeneratePage.class);
        body.add(this.createButton);
    }

    protected List<ActionItem> root_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>(0);
        String status = model.get("status", String.class);
        actions.add(new ActionItem("Copy", Model.of("Copy"), ItemCss.SUCCESS));
        if ("Good".equals(status)) {
            actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.DANGER));
        }
        return actions;
    }

    protected void root_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        if ("Revoke".equals(link)) {
            long uuid = model.get("uuid", long.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(RootRevokePage.class, parameters);
        } else if ("Copy".equals(link)) {
            long uuid = model.get("uuid", long.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(RootGeneratePage.class, parameters);
        }
    }

}

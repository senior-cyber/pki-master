package com.senior.cyber.pki.issuer.web.pages.csr;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.TabbedPanel;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.issuer.web.pages.MasterPage;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;

import java.util.ArrayList;
import java.util.List;

@Bookmark("/csr/submit")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_CsrSubmit})
public class CsrSubmitPage extends MasterPage {

    protected TabbedPanel tabs;

    protected Tab info_tab;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.info_tab = new Tab("info", "Information", CsrSubmitPageInfoTab.class);
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        List<Tab> tabs = new ArrayList<>();
        if (this.info_tab != null) {
            tabs.add(this.info_tab);
        }
        this.tabs = new TabbedPanel("tabs", tabs);
        body.add(this.tabs);
    }

}

//package com.senior.cyber.pki.issuer.web.pages.my.issuer;
//
//import com.senior.cyber.frmk.common.base.Bookmark;
//import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
//import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.TabbedPanel;
//import com.senior.cyber.pki.dao.entity.Role;
//import com.senior.cyber.pki.issuer.web.pages.MasterPage;
//import org.apache.wicket.MarkupContainer;
//import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
//
//import java.util.ArrayList;
//import java.util.List;
//
//@Bookmark("/my/issuer/revoke")
//@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyIntermediateRevoke})
//public class IssuerRevokePage extends MasterPage {
//
//    protected TabbedPanel tabs;
//
//    protected Tab info_tab;
//
//    @Override
//    protected void onInitData() {
//        super.onInitData();
//        this.info_tab = new Tab("info", "Information", IssuerRevokePageInfoTab.class);
//    }
//
//    @Override
//    protected void onInitHtml(MarkupContainer body) {
//        List<Tab> tabs = new ArrayList<>();
//        if (this.info_tab != null) {
//            tabs.add(this.info_tab);
//        }
//        this.tabs = new TabbedPanel("tabs", tabs);
//        body.add(this.tabs);
//    }
//
//}

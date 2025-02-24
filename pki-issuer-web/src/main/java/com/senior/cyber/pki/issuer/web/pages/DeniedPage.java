package com.senior.cyber.pki.issuer.web.pages;

import com.senior.cyber.frmk.common.base.AdminLTEResourceReference;
import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.LTEAdminProperties;
import org.apache.wicket.markup.head.CssHeaderItem;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.resource.FileSystemResourceReference;

import java.io.File;
import java.util.UUID;

@Bookmark("/denied")
public class DeniedPage extends WebPage {

    @Override
    protected void onInitialize() {
        super.onInitialize();
        String page = getPageParameters().get("page").toString();
        Label pageNameLabel = new Label("pageName", page);
        add(pageNameLabel);
        pageNameLabel.setVisible(page != null && !"".equals(page));
        add(new Label("role", getPageParameters().get("role").toString()));
        add(new BookmarkablePageLink<>("loginPage", LoginPage.class));
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        File adminLte = ((LTEAdminProperties) WebApplication.get()).getWebUiProperties().getAdminLte();
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/@fontsource/source-sans-3@5.0.12/index.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/overlayscrollbars@2.10.1/styles/overlayscrollbars.min.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"));
        response.render(CssHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, "/css/adminlte.css").getPath())));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/apexcharts@3.37.1/dist/apexcharts.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/overlayscrollbars@2.10.1/browser/overlayscrollbars.browser.es6.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"));
        response.render(JavaScriptHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, "/js/adminlte.js").getPath())));
        StringBuilder js = new StringBuilder();
        js.append("<script>").append("\n");
        js.append("    const SELECTOR_SIDEBAR_WRAPPER = \".sidebar-wrapper\";").append("\n");
        js.append("    const Default = {").append("\n");
        js.append("        scrollbarTheme: \"os-theme-light\",").append("\n");
        js.append("        scrollbarAutoHide: \"leave\",").append("\n");
        js.append("        scrollbarClickScroll: true,").append("\n");
        js.append("    };").append("\n");
        js.append("    document.addEventListener(\"DOMContentLoaded\", function () {").append("\n");
        js.append("        const sidebarWrapper = document.querySelector(SELECTOR_SIDEBAR_WRAPPER);").append("\n");
        js.append("        if (").append("\n");
        js.append("            sidebarWrapper &&").append("\n");
        js.append("            typeof OverlayScrollbarsGlobal?.OverlayScrollbars !== \"undefined\"").append("\n");
        js.append("        ) {").append("\n");
        js.append("            OverlayScrollbarsGlobal.OverlayScrollbars(sidebarWrapper, {").append("\n");
        js.append("                scrollbars: {").append("\n");
        js.append("                    theme: Default.scrollbarTheme,").append("\n");
        js.append("                    autoHide: Default.scrollbarAutoHide,").append("\n");
        js.append("                    clickScroll: Default.scrollbarClickScroll,").append("\n");
        js.append("                },").append("\n");
        js.append("            });").append("\n");
        js.append("        }").append("\n");
        js.append("    });").append("\n");
        js.append("</script>").append("\n");
        response.render(JavaScriptHeaderItem.forScript(js.toString(), UUID.randomUUID().toString()));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/apexcharts@3.37.1/dist/apexcharts.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/js/jsvectormap.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/maps/world.js"));
    }

}
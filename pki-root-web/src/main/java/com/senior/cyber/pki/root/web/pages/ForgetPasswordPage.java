package com.senior.cyber.pki.root.web.pages;

import com.senior.cyber.frmk.common.base.AdminLTEResourceReference;
import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.LTEAdminProperties;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ComponentFeedbackPanel;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.root.web.factory.WicketFactory;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.wicket.markup.head.CssHeaderItem;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.resource.FileSystemResourceReference;
import org.apache.wicket.validation.ValidationError;
import org.apache.wicket.validation.validator.EmailAddressValidator;
import org.jasypt.util.password.PasswordEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.util.Optional;
import java.util.UUID;

@Bookmark("/forget/password")
public class ForgetPasswordPage extends WebPage {

    private static final Logger LOGGER = LoggerFactory.getLogger(ForgetPasswordPage.class);

    protected Form<Void> form = null;

    protected TextField<String> email_address_field;
    protected ComponentFeedbackPanel email_address_feedback;
    protected String email_address_value;

    protected Button okayButton;

    @Override
    protected void onInitialize() {
        super.onInitialize();
        this.form = new Form<>("form");
        add(this.form);

        this.email_address_field = new TextField<>("email_address_field", new PropertyModel<>(this, "email_address_value"));
        this.email_address_field.setLabel(Model.of("Email Address"));
        this.email_address_field.setRequired(true);
        this.email_address_field.add(EmailAddressValidator.getInstance());
        this.form.add(this.email_address_field);
        this.email_address_feedback = new ComponentFeedbackPanel("email_address_feedback", this.email_address_field);
        this.form.add(this.email_address_feedback);

        this.okayButton = new Button("okayButton") {
            @Override
            public void onSubmit() {
                okayButtonClick();
            }
        };
        this.form.add(this.okayButton);

        add(new BookmarkablePageLink<>("loginPage", LoginPage.class));
    }

    protected void okayButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        PasswordEncryptor passwordEncryptor = context.getBean(PasswordEncryptor.class);
        Optional<User> optionalUser = userRepository.findByEmailAddress(this.email_address_value);
        User user = optionalUser.orElse(null);
        if (user == null) {
            this.email_address_field.error(new ValidationError(this.email_address_value + " is not found"));
        } else {
            String password = RandomStringUtils.randomAlphabetic(10);
            user.setPassword(passwordEncryptor.encryptPassword(password));
            LOGGER.info("password [{}]", password);
            userRepository.save(user);
            setResponsePage(new RecoverPasswordPage(user.getId()));
        }
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        File adminLte = ((LTEAdminProperties) WebApplication.get()).getWebUiProperties().getAdminLte();
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/@fontsource/source-sans-3@5.0.12/index.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/overlayscrollbars@2.10.1/styles/overlayscrollbars.min.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"));
        response.render(CssHeaderItem.forReference(new PackageResourceReference(Pkg.class, "v4.0.0-beta3/css/adminlte.css")));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/apexcharts@3.37.1/dist/apexcharts.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/overlayscrollbars@2.10.1/browser/overlayscrollbars.browser.es6.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"));
        response.render(JavaScriptHeaderItem.forReference(new PackageResourceReference(Pkg.class, "v4.0.0-beta3/js/adminlte.js")));
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

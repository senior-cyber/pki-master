package com.senior.cyber.pki.issuer.web.pages;

import com.senior.cyber.frmk.common.Pkg;
import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.LTEAdminProperties;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ComponentFeedbackPanel;
import com.senior.cyber.pki.dao.entity.Group;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.repository.GroupRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
import com.senior.cyber.pki.issuer.web.validator.UserEmailAddressValidator;
import com.senior.cyber.pki.issuer.web.validator.UserLoginValidator;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.markup.head.CssHeaderItem;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.form.validation.EqualPasswordInputValidator;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.request.resource.PackageResourceReference;
import org.apache.wicket.resource.FileSystemResourceReference;
import org.apache.wicket.validation.validator.EmailAddressValidator;
import org.jasypt.util.password.PasswordEncryptor;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.util.*;

@Bookmark("/register")
public class RegisterPage extends WebPage {

    protected Form<Void> form = null;

    protected TextField<String> display_name_field;
    protected ComponentFeedbackPanel display_name_feedback;
    protected String display_name_value;

    protected TextField<String> email_address_field;
    protected ComponentFeedbackPanel email_address_feedback;
    protected String email_address_value;

    protected TextField<String> username_field;
    protected ComponentFeedbackPanel username_feedback;
    protected String username_value;

    protected PasswordTextField password_field;
    protected ComponentFeedbackPanel password_feedback;
    protected String password_value;

    protected PasswordTextField retype_password_field;
    protected ComponentFeedbackPanel retype_password_feedback;
    protected String retype_password_value;

    protected Button registerButton;

    @Override
    protected void onInitialize() {
        super.onInitialize();
        this.form = new Form<>("form");
        add(this.form);

        this.display_name_field = new TextField<>("display_name_field", new PropertyModel<>(this, "display_name_value"));
        this.display_name_field.setLabel(Model.of("Display Name"));
        this.display_name_field.setRequired(true);
        this.form.add(this.display_name_field);
        this.display_name_feedback = new ComponentFeedbackPanel("display_name_feedback", this.display_name_field);
        this.form.add(this.display_name_feedback);

        this.email_address_field = new TextField<>("email_address_field", new PropertyModel<>(this, "email_address_value"));
        this.email_address_field.setLabel(Model.of("Email Address"));
        this.email_address_field.setRequired(true);
        this.email_address_field.add(new UserEmailAddressValidator());
        this.email_address_field.add(EmailAddressValidator.getInstance());
        this.form.add(this.email_address_field);
        this.email_address_feedback = new ComponentFeedbackPanel("email_address_feedback", this.email_address_field);
        this.form.add(this.email_address_feedback);

        this.username_field = new TextField<>("username_field", new PropertyModel<>(this, "username_value"));
        this.username_field.setLabel(Model.of("Username"));
        this.username_field.setRequired(true);
        this.username_field.add(new UserLoginValidator());
        this.form.add(this.username_field);
        this.username_feedback = new ComponentFeedbackPanel("username_feedback", this.username_field);
        this.form.add(this.username_feedback);

        this.password_field = new PasswordTextField("password_field", new PropertyModel<>(this, "password_value"));
        this.password_field.setLabel(Model.of("Password"));
        this.password_field.setRequired(true);
        this.form.add(this.password_field);
        this.password_feedback = new ComponentFeedbackPanel("password_feedback", this.password_field);
        this.form.add(this.password_feedback);

        this.retype_password_field = new PasswordTextField("retype_password_field", new PropertyModel<>(this, "retype_password_value"));
        this.retype_password_field.setLabel(Model.of("Retype Password"));
        this.retype_password_field.setRequired(true);
        this.form.add(this.retype_password_field);
        this.retype_password_feedback = new ComponentFeedbackPanel("retype_password_feedback", this.retype_password_field);
        this.form.add(this.retype_password_feedback);

        this.form.add(new EqualPasswordInputValidator(this.password_field, this.retype_password_field));

        this.registerButton = new Button("registerButton") {
            @Override
            public void onSubmit() {
                registerButtonClick();
            }
        };
        this.form.add(this.registerButton);

        add(new BookmarkablePageLink<>("loginPage", LoginPage.class));
    }

    protected void registerButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        GroupRepository groupRepository = context.getBean(GroupRepository.class);
        PasswordEncryptor passwordEncryptor = context.getBean(PasswordEncryptor.class);

        Optional<Group> optionalGroup = groupRepository.findByName("Registered");
        Group group = optionalGroup.orElseThrow(() -> new WicketRuntimeException(""));

        User user = new User();
        user.setDisplayName(this.display_name_value);
        user.setEnabled(true);
        user.setEmailAddress(this.email_address_value);
        user.setLogin(this.username_value);
        user.setLastSeen(new Date());
        user.setPassword(passwordEncryptor.encryptPassword(this.password_value));
        Map<String, Group> groups = new HashMap<>();
        groups.put(UUID.randomUUID().toString(), group);
        user.setGroups(groups);
        userRepository.save(user);

        setResponsePage(LoginPage.class);
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

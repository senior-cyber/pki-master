package com.senior.cyber.pki.issuer.web.pages;

import com.senior.cyber.frmk.common.base.AdminLTEResourceReference;
import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ComponentFeedbackPanel;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
import com.senior.cyber.pki.issuer.web.repository.UserRepository;
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
import org.apache.wicket.validation.ValidationError;
import org.apache.wicket.validation.validator.EmailAddressValidator;
import org.jasypt.util.password.PasswordEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import java.util.Optional;

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
        // <!-- Font Awesome -->
        response.render(CssHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.CSS_FONT_AWESOME)));
        // <!-- Ionicons -->
        response.render(CssHeaderItem.forUrl(AdminLTEResourceReference.CSS_ION_ICONS));
        // <!-- icheck bootstrap -->
        response.render(CssHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.CSS_ICHECK_BOOTSTRAP)));
        // <!-- Theme style -->
        response.render(CssHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.CSS_THEME_STYLE)));
        // <!-- Google Font: Source Sans Pro -->
        response.render(CssHeaderItem.forUrl(AdminLTEResourceReference.CSS_GOOGLE_FONT));

        response.render(JavaScriptHeaderItem.forReference(getApplication().getJavaScriptLibrarySettings().getJQueryReference()));

        // <!-- Bootstrap 4 -->
        response.render(JavaScriptHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.JS_BOOTSTRAP_4)));
        // <!-- AdminLTE App -->
        response.render(JavaScriptHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.JS_ADMINLTE_APP)));
    }

}

package com.senior.cyber.pki.web.pages.my.profile;

import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.webui.frmk.common.WicketFactory;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.webui.frmk.wicket.layout.Size;
import com.senior.cyber.webui.frmk.wicket.layout.UIColumn;
import com.senior.cyber.webui.frmk.wicket.layout.UIContainer;
import com.senior.cyber.webui.frmk.wicket.layout.UIRow;
import com.senior.cyber.webui.frmk.wicket.markup.html.panel.ContainerFeedbackBehavior;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.springframework.context.ApplicationContext;

import java.util.Map;
import java.util.Optional;

public class MyProfilePageInfoTab extends ContentPanel {

    protected long uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn email_address_column;
    protected UIContainer email_address_container;
    protected TextField<String> email_address_field;
    protected String email_address_value;

    protected UIRow row2;

    protected UIColumn display_name_column;
    protected UIContainer display_name_container;
    protected TextField<String> display_name_field;
    protected String display_name_value;

    protected Button saveButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public MyProfilePageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        WebSession session = (WebSession) getWebSession();
        this.uuid = session.getUserId();
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        Optional<User> userOptional = userRepository.findById(this.uuid);
        User user = userOptional.orElseThrow();
        this.display_name_value = user.getDisplayName();
        this.email_address_value = user.getEmailAddress();
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.email_address_column = this.row1.newUIColumn("email_address_column", Size.Six_6);
        this.email_address_container = this.email_address_column.newUIContainer("email_address_container");
        this.email_address_field = new TextField<>("email_address_field", new PropertyModel<>(this, "email_address_value"));
        this.email_address_field.setLabel(Model.of("Email Address"));
        this.email_address_field.setEnabled(false);
        this.email_address_field.add(new ContainerFeedbackBehavior());
        this.email_address_container.add(this.email_address_field);
        this.email_address_container.newFeedback("email_address_feedback", this.email_address_field);

        this.row1.lastUIColumn("last_column");

        this.row2 = UIRow.newUIRow("row2", this.form);

        this.display_name_column = this.row2.newUIColumn("display_name_column", Size.Six_6);
        this.display_name_container = this.display_name_column.newUIContainer("display_name_container");
        this.display_name_field = new TextField<>("display_name_field", new PropertyModel<>(this, "display_name_value"));
        this.display_name_field.setLabel(Model.of("Mobile Phone Number"));
        this.display_name_field.setRequired(true);
        this.display_name_field.add(new ContainerFeedbackBehavior());
        this.display_name_container.add(this.display_name_field);
        this.display_name_container.newFeedback("display_name_feedback", this.display_name_field);

        this.row2.lastUIColumn("last_column");

        this.saveButton = new Button("saveButton") {
            @Override
            public void onSubmit() {
                saveButtonClick();
            }
        };
        this.form.add(this.saveButton);

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", MyProfilePage.class);
        this.form.add(this.cancelButton);
    }

    protected void saveButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        Optional<User> userOptional = userRepository.findById(this.uuid);
        User user = userOptional.orElseThrow();
        user.setDisplayName(this.display_name_value);
        user.setEmailAddress(this.email_address_value);
        userRepository.save(user);
        setResponsePage(MyProfilePage.class);
    }

}

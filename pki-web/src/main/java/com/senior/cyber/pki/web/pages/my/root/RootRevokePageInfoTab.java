package com.senior.cyber.pki.web.pages.my.root;


import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.repository.CertificateRepository;
import com.senior.cyber.pki.web.repository.IntermediateRepository;
import com.senior.cyber.pki.web.repository.RootRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.webui.frmk.common.WicketFactory;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.webui.frmk.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.webui.frmk.wicket.layout.Size;
import com.senior.cyber.webui.frmk.wicket.layout.UIColumn;
import com.senior.cyber.webui.frmk.wicket.layout.UIContainer;
import com.senior.cyber.webui.frmk.wicket.layout.UIRow;
import com.senior.cyber.webui.frmk.wicket.markup.html.form.DateTextField;
import com.senior.cyber.webui.frmk.wicket.markup.html.panel.ContainerFeedbackBehavior;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.DropDownChoice;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.joda.time.LocalDate;
import org.springframework.context.ApplicationContext;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class RootRevokePageInfoTab extends ContentPanel {

    protected long uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn date_column;
    protected UIContainer date_container;
    protected DateTextField date_field;
    protected Date date_value;

    protected UIColumn reason_column;
    protected UIContainer reason_container;
    protected DropDownChoice<String> reason_field;
    protected List<String> reason_provider;
    protected String reason_value;

    protected UIRow row2;

    protected UIColumn common_name_column;
    protected UIContainer common_name_container;
    protected TextField<String> common_name_field;
    protected String common_name_value;

    protected UIColumn organization_column;
    protected UIContainer organization_container;
    protected TextField<String> organization_field;
    protected String organization_value;

    protected UIColumn organizational_unit_column;
    protected UIContainer organizational_unit_container;
    protected TextField<String> organizational_unit_field;
    protected String organizational_unit_value;

    protected UIRow row3;

    protected UIColumn locality_name_column;
    protected UIContainer locality_name_container;
    protected TextField<String> locality_name_field;
    protected String locality_name_value;

    protected UIColumn state_or_province_name_column;
    protected UIContainer state_or_province_name_container;
    protected TextField<String> state_or_province_name_field;
    protected String state_or_province_name_value;

    protected UIColumn country_column;
    protected UIContainer country_container;
    protected TextField<String> country_field;
    protected String country_value;

    protected UIRow row4;

    protected UIColumn email_address_column;
    protected UIContainer email_address_container;
    protected TextField<String> email_address_field;
    protected String email_address_value;

    protected Button revokeButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public RootRevokePageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        this.reason_provider = List.of("unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aACompromise");
        WebSession session = (WebSession) getSession();
        this.uuid = getPage().getPageParameters().get("uuid").toLong(-1L);
        ApplicationContext context = WicketFactory.getApplicationContext();
        RootRepository rootRepository = context.getBean(RootRepository.class);
        UserRepository userRepository = context.getBean(UserRepository.class);
        Optional<User> optionalUser = userRepository.findById(session.getUserId());
        User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
        Optional<Root> optionalRoot = rootRepository.findByIdAndUser(this.uuid, user);
        Root root = optionalRoot.orElseThrow(() -> new WicketRuntimeException(""));
        this.common_name_value = root.getCommonName();
        this.organization_value = root.getOrganization();
        this.organizational_unit_value = root.getOrganizationalUnit();
        this.locality_name_value = root.getLocalityName();
        this.state_or_province_name_value = root.getStateOrProvinceName();
        this.country_value = root.getCountryCode();
        this.email_address_value = root.getEmailAddress();

        this.date_value = LocalDate.now().toDate();
        this.reason_value = "cessationOfOperation";
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.date_column = this.row1.newUIColumn("date_column", Size.Four_4);
        this.date_container = this.date_column.newUIContainer("date_container");
        this.date_field = new DateTextField("date_field", new PropertyModel<>(this, "date_value"));
        this.date_field.setLabel(Model.of("Date"));
        this.date_field.setRequired(true);
        this.date_field.add(new ContainerFeedbackBehavior());
        this.date_container.add(this.date_field);
        this.date_container.newFeedback("date_feedback", this.date_field);

        this.reason_column = this.row1.newUIColumn("reason_column", Size.Four_4);
        this.reason_container = this.reason_column.newUIContainer("reason_container");
        this.reason_field = new DropDownChoice<>("reason_field", new PropertyModel<>(this, "reason_value"), this.reason_provider);
        this.reason_field.setLabel(Model.of("Reason"));
        this.reason_field.setRequired(true);
        this.reason_field.add(new ContainerFeedbackBehavior());
        this.reason_container.add(this.reason_field);
        this.reason_container.newFeedback("reason_feedback", this.reason_field);

        this.row1.lastUIColumn("last_column");

        this.row2 = UIRow.newUIRow("row2", this.form);

        this.common_name_column = this.row2.newUIColumn("common_name_column", Size.Four_4);
        this.common_name_container = this.common_name_column.newUIContainer("common_name_container");
        this.common_name_field = new TextField<>("common_name_field", new PropertyModel<>(this, "common_name_value"));
        this.common_name_field.setLabel(Model.of("Common Name"));
        this.common_name_field.add(new ContainerFeedbackBehavior());
        this.common_name_field.setEnabled(false);
        this.common_name_container.add(this.common_name_field);
        this.common_name_container.newFeedback("common_name_feedback", this.common_name_field);

        this.organization_column = this.row2.newUIColumn("organization_column", Size.Four_4);
        this.organization_container = this.organization_column.newUIContainer("organization_container");
        this.organization_field = new TextField<>("organization_field", new PropertyModel<>(this, "organization_value"));
        this.organization_field.setLabel(Model.of("Organization"));
        this.organization_field.add(new ContainerFeedbackBehavior());
        this.organization_field.setEnabled(false);
        this.organization_container.add(this.organization_field);
        this.organization_container.newFeedback("organization_feedback", this.organization_field);

        this.organizational_unit_column = this.row2.newUIColumn("organizational_unit_column", Size.Four_4);
        this.organizational_unit_container = this.organizational_unit_column.newUIContainer("organizational_unit_container");
        this.organizational_unit_field = new TextField<>("organizational_unit_field", new PropertyModel<>(this, "organizational_unit_value"));
        this.organizational_unit_field.setLabel(Model.of("Organizational Unit"));
        this.organizational_unit_field.add(new ContainerFeedbackBehavior());
        this.organizational_unit_field.setEnabled(false);
        this.organizational_unit_container.add(this.organizational_unit_field);
        this.organizational_unit_container.newFeedback("organizational_unit_feedback", this.organizational_unit_field);

        this.row2.lastUIColumn("last_column");

        this.row3 = UIRow.newUIRow("row3", this.form);

        this.locality_name_column = this.row3.newUIColumn("locality_name_column", Size.Four_4);
        this.locality_name_container = this.locality_name_column.newUIContainer("locality_name_container");
        this.locality_name_field = new TextField<>("locality_name_field", new PropertyModel<>(this, "locality_name_value"));
        this.locality_name_field.setLabel(Model.of("Locality"));
        this.locality_name_field.add(new ContainerFeedbackBehavior());
        this.locality_name_field.setEnabled(false);
        this.locality_name_container.add(this.locality_name_field);
        this.locality_name_container.newFeedback("locality_name_feedback", this.locality_name_field);

        this.state_or_province_name_column = this.row3.newUIColumn("state_or_province_name_column", Size.Four_4);
        this.state_or_province_name_container = this.state_or_province_name_column.newUIContainer("state_or_province_name_container");
        this.state_or_province_name_field = new TextField<>("state_or_province_name_field", new PropertyModel<>(this, "state_or_province_name_value"));
        this.state_or_province_name_field.setLabel(Model.of("State / Province"));
        this.state_or_province_name_field.add(new ContainerFeedbackBehavior());
        this.state_or_province_name_field.setEnabled(false);
        this.state_or_province_name_container.add(this.state_or_province_name_field);
        this.state_or_province_name_container.newFeedback("state_or_province_name_feedback", this.state_or_province_name_field);

        this.country_column = this.row3.newUIColumn("country_column", Size.Four_4);
        this.country_container = this.country_column.newUIContainer("country_container");
        this.country_field = new TextField<>("country_field", new PropertyModel<>(this, "country_value"));
        this.country_field.setLabel(Model.of("Country Code"));
        this.country_field.add(new ContainerFeedbackBehavior());
        this.country_field.setEnabled(false);
        this.country_container.add(this.country_field);
        this.country_container.newFeedback("country_feedback", this.country_field);

        this.row3.lastUIColumn("last_column");

        this.row4 = UIRow.newUIRow("row4", this.form);

        this.email_address_column = this.row4.newUIColumn("email_address_column", Size.Twelve_12);
        this.email_address_container = this.email_address_column.newUIContainer("email_address_container");
        this.email_address_field = new TextField<>("email_address_field", new PropertyModel<>(this, "email_address_value"));
        this.email_address_field.setLabel(Model.of("Email Address"));
        this.email_address_field.add(new ContainerFeedbackBehavior());
        this.email_address_field.setEnabled(false);
        this.email_address_container.add(this.email_address_field);
        this.email_address_container.newFeedback("email_address_feedback", this.email_address_field);

        this.row4.lastUIColumn("last_column");

        this.revokeButton = new Button("revokeButton") {
            @Override
            public void onSubmit() {
                revokeButtonClick();
            }
        };
        this.form.add(this.revokeButton);

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", RootBrowsePage.class);
        this.form.add(this.cancelButton);
    }

    protected void revokeButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        RootRepository rootRepository = context.getBean(RootRepository.class);
        IntermediateRepository intermediateRepository = context.getBean(IntermediateRepository.class);
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);

        Optional<Root> optionalRoot = rootRepository.findById(this.uuid);
        Root root = optionalRoot.orElseThrow(() -> new WicketRuntimeException(""));

        root.setRevokedDate(this.date_value);
        root.setStatus("Revoked");
        rootRepository.save(root);

        List<Intermediate> intermediates = intermediateRepository.findByRootAndStatus(root, "Good");
        for (Intermediate intermediate : intermediates) {
            intermediate.setRevokedDate(this.date_value);
            intermediate.setRevokedReason(this.reason_value);
            intermediate.setStatus("Revoked");
            intermediateRepository.save(intermediate);
            List<Certificate> certificates = certificateRepository.findByIntermediateAndStatus(intermediate, "Good");
            for (Certificate certificate : certificates) {
                certificate.setRevokedDate(this.date_value);
                certificate.setRevokedReason(this.reason_value);
                certificate.setStatus("Revoked");
                certificateRepository.save(certificate);
            }
        }

        setResponsePage(RootBrowsePage.class);
    }

}

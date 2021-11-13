package com.senior.cyber.pki.web.pages.my.certificate;


import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.form.DateTextField;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.web.configuration.Mode;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.repository.CertificateRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.*;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.joda.time.LocalDate;
import org.springframework.context.ApplicationContext;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class CertificateRevokePageInfoTab extends ContentPanel {

    protected long uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn issuer_column;
    protected UIContainer issuer_container;
    protected TextField<String> issuer_field;
    protected String issuer_value;

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

    protected UIRow row5;

    protected UIColumn san_column;
    protected UIContainer san_container;
    protected TextArea<String> san_field;
    protected String san_value;

    protected Button revokeButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public CertificateRevokePageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        this.reason_provider = List.of("unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aACompromise");
        WebSession session = (WebSession) getSession();
        this.uuid = getPage().getPageParameters().get("uuid").toLong(-1L);
        ApplicationContext context = WicketFactory.getApplicationContext();
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
        UserRepository userRepository = context.getBean(UserRepository.class);
        Optional<User> optionalUser = userRepository.findById(session.getUserId());
        User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
        Optional<Certificate> optionalCertificate = certificateRepository.findByIdAndUser(this.uuid, user);
        Certificate certificate = optionalCertificate.orElseThrow(() -> new WicketRuntimeException(""));
        this.common_name_value = certificate.getCommonName();
        this.organization_value = certificate.getOrganization();
        this.organizational_unit_value = certificate.getOrganizationalUnit();
        this.locality_name_value = certificate.getLocalityName();
        this.state_or_province_name_value = certificate.getStateOrProvinceName();
        this.country_value = certificate.getCountryCode();
        this.email_address_value = certificate.getEmailAddress();
        this.san_value = certificate.getSan();
        this.issuer_value = certificate.getIntermediate().getCommonName();

        this.date_value = LocalDate.now().toDate();
        this.reason_value = "cessationOfOperation";
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.issuer_column = this.row1.newUIColumn("issuer_column", Size.Four_4);
        this.issuer_container = this.issuer_column.newUIContainer("issuer_container");
        this.issuer_field = new TextField<>("issuer_field", new PropertyModel<>(this, "issuer_value"));
        this.issuer_field.setLabel(Model.of("Issuer"));
        this.issuer_field.add(new ContainerFeedbackBehavior());
        this.issuer_field.setEnabled(false);
        this.issuer_container.add(this.issuer_field);
        this.issuer_container.newFeedback("issuer_feedback", this.issuer_field);

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

        this.row5 = UIRow.newUIRow("row5", this.form);

        this.san_column = this.row5.newUIColumn("san_column", Size.Twelve_12);
        this.san_container = this.san_column.newUIContainer("san_container");
        this.san_field = new TextArea<>("san_field", new PropertyModel<>(this, "san_value"));
        this.san_field.setLabel(Model.of("Subject Alternative Name"));
        this.san_field.add(new ContainerFeedbackBehavior());
        this.san_field.setEnabled(false);
        this.san_container.add(this.san_field);
        this.san_container.newFeedback("san_feedback", this.san_field);

        this.row5.lastUIColumn("last_column");

        this.revokeButton = new Button("revokeButton") {
            @Override
            public void onSubmit() {
                revokeButtonClick();
            }
        };
        this.form.add(this.revokeButton);

        WebSession session = (WebSession) getSession();
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (session.getRoles().hasRole(Role.NAME_ROOT) || session.getRoles().hasRole(Role.NAME_Page_MyCertificateRevoke_Revoke_Action)) {
                this.revokeButton.setVisible(true);
            } else {
                this.revokeButton.setVisible(false);
            }
        }

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", CertificateBrowsePage.class);
        this.form.add(this.cancelButton);
    }

    protected void revokeButtonClick() {
        WebSession session = (WebSession) getSession();
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (session.getRoles().hasRole(Role.NAME_ROOT) || session.getRoles().hasRole(Role.NAME_Page_MyCertificateRevoke_Revoke_Action)) {
            } else {
                throw new WicketRuntimeException("No Permission");
            }
        }

        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);

        Optional<Certificate> optionalCertificate = certificateRepository.findById(this.uuid);
        Certificate certificate = optionalCertificate.orElseThrow(() -> new WicketRuntimeException(""));

        certificate.setRevokedDate(this.date_value);
        certificate.setRevokedReason(this.reason_value);

        certificate.setStatus("Revoked");

        certificateRepository.save(certificate);

        setResponsePage(CertificateBrowsePage.class);
    }

}

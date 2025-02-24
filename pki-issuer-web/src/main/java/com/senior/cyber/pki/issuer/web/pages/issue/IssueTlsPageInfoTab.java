package com.senior.cyber.pki.issuer.web.pages.issue;

import com.senior.cyber.frmk.common.jackson.CsrDeserializer;
import com.senior.cyber.frmk.common.jakarta.persistence.Sql;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.form.DateTextField;
import com.senior.cyber.frmk.common.wicket.markup.html.form.FileUploadField;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Option;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Select2SingleChoice;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.pki.common.dto.CertificateTlsCsrRequest;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Certificate_;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.IssuerWebApplication;
import com.senior.cyber.pki.issuer.web.configuration.ApiConfiguration;
import com.senior.cyber.pki.issuer.web.data.Select2ChoiceProvider;
import com.senior.cyber.pki.issuer.web.factory.WebSession;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
import com.senior.cyber.pki.issuer.web.pages.my.certificate.CertificateBrowsePage;
import com.senior.cyber.pki.issuer.web.validator.*;
import com.senior.cyber.pki.service.CertificateService;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;
import org.springframework.context.ApplicationContext;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class IssueTlsPageInfoTab extends ContentPanel {

    protected Certificate issuerCertificate;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn csr_column;
    protected UIContainer csr_container;
    protected FileUploadField csr_field;
    protected List<FileUpload> csr_value;

    protected UIRow row2;

    protected UIColumn issuer_column;
    protected UIContainer issuer_container;
    protected Select2SingleChoice issuer_field;
    protected Select2ChoiceProvider issuer_provider;
    protected Option issuer_value;

    protected UIColumn valid_from_column;
    protected UIContainer valid_from_container;
    protected DateTextField valid_from_field;
    protected Date valid_from_value;

    protected UIColumn valid_until_column;
    protected UIContainer valid_until_container;
    protected DateTextField valid_until_field;
    protected Date valid_until_value;

    protected UIRow row3;

    protected UIColumn ip_column;
    protected UIContainer ip_container;
    protected TextField<String> ip_field;
    protected String ip_value;

    protected UIRow row4;

    protected UIColumn dns_column;
    protected UIContainer dns_container;
    protected TextField<String> dns_field;
    protected String dns_value;

    protected Button saveButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public IssueTlsPageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        WebSession session = (WebSession) getSession();
        ApplicationContext context = WicketFactory.getApplicationContext();
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);

        UserRepository userRepository = context.getBean(UserRepository.class);
        Optional<User> optionalUser = userRepository.findById(session.getUserId());
        User user = optionalUser.orElseThrow();

        PageParameters parameters = getPage().getPageParameters();
        long serial = parameters.get("serial").toLong(0L);
        Optional<Certificate> optionalIssuerCertificate = certificateRepository.findBySerialAndUser(serial, user);
        this.issuerCertificate = optionalIssuerCertificate.orElse(null);

        if (this.issuerCertificate != null) {
            this.issuer_value = new Option(String.valueOf(this.issuerCertificate.getSerial()), this.issuerCertificate.getCommonName());
        }

        this.issuer_provider = new Select2ChoiceProvider(Sql.table(Certificate_.class), Sql.column(Certificate_.serial), Sql.column(Certificate_.commonName));
        this.issuer_provider.applyWhere("status", Sql.column(Certificate_.status) + " = '" + CertificateStatusEnum.Good.name() + "'");
        this.issuer_provider.applyWhere("type", Sql.column(Certificate_.type) + " = '" + CertificateTypeEnum.Issuer.name() + "'");
        this.issuer_provider.applyWhere("user", Sql.column(Certificate_.user) + " = '" + session.getUserId() + "'");
        LocalDate now = LocalDate.now();

        this.valid_from_value = now.toDate();
        this.valid_until_value = now.plusYears(1).toDate();
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.csr_column = this.row1.newUIColumn("csr_column", Size.Twelve_12);
        this.csr_container = this.csr_column.newUIContainer("csr_container");
        this.csr_field = new FileUploadField("csr_field", new PropertyModel<>(this, "csr_value"));
        this.csr_field.setLabel(Model.of("CSR"));
        this.csr_field.setRequired(true);
        this.csr_field.add(new CsrValidator());
        this.csr_field.add(new ContainerFeedbackBehavior());
        this.csr_container.add(this.csr_field);
        this.csr_container.newFeedback("csr_feedback", this.csr_field);

        this.row1.lastUIColumn("last_column");

        this.row2 = UIRow.newUIRow("row2", this.form);

        this.issuer_column = this.row2.newUIColumn("issuer_column", Size.Four_4);
        this.issuer_container = this.issuer_column.newUIContainer("issuer_container");
        this.issuer_field = new Select2SingleChoice("issuer_field", new PropertyModel<>(this, "issuer_value"), this.issuer_provider);
        this.issuer_field.setLabel(Model.of("Issuer"));
        this.issuer_field.setRequired(true);
        this.issuer_field.add(new ContainerFeedbackBehavior());
        this.issuer_container.add(this.issuer_field);
        this.issuer_container.newFeedback("issuer_feedback", this.issuer_field);
        if (this.issuerCertificate != null) {
            this.issuer_field.setEnabled(false);
        }

        this.valid_from_column = this.row2.newUIColumn("valid_from_column", Size.Four_4);
        this.valid_from_container = this.valid_from_column.newUIContainer("valid_from_container");
        this.valid_from_field = new DateTextField("valid_from_field", new PropertyModel<>(this, "valid_from_value"));
        this.valid_from_field.setRequired(true);
        this.valid_from_field.setLabel(Model.of("Valid From"));
        this.valid_from_field.add(new ContainerFeedbackBehavior());
        this.valid_from_container.add(this.valid_from_field);
        this.valid_from_container.newFeedback("valid_from_feedback", this.valid_from_field);

        this.valid_until_column = this.row2.newUIColumn("valid_until_column", Size.Four_4);
        this.valid_until_container = this.valid_until_column.newUIContainer("valid_until_container");
        this.valid_until_field = new DateTextField("valid_until_field", new PropertyModel<>(this, "valid_until_value"));
        this.valid_until_field.setRequired(true);
        this.valid_until_field.setLabel(Model.of("Valid Until"));
        this.valid_until_field.add(new ContainerFeedbackBehavior());
        this.valid_until_container.add(this.valid_until_field);
        this.valid_until_container.newFeedback("valid_until_feedback", this.valid_until_field);

        this.row2.lastUIColumn("last_column");

        this.row3 = UIRow.newUIRow("row3", this.form);

        this.ip_column = this.row3.newUIColumn("ip_column", Size.Twelve_12);
        this.ip_container = this.ip_column.newUIContainer("ip_container");
        this.ip_field = new TextField<>("ip_field", new PropertyModel<>(this, "ip_value"));
        this.ip_field.setLabel(Model.of("Subject Alternative Name"));
        this.ip_field.add(new ContainerFeedbackBehavior());
        this.ip_field.add(new CertificateIpValidator());
        this.ip_container.add(this.ip_field);
        this.ip_container.newFeedback("ip_feedback", this.ip_field);

        this.row3.lastUIColumn("last_column");

        this.row4 = UIRow.newUIRow("row4", this.form);

        this.dns_column = this.row4.newUIColumn("dns_column", Size.Twelve_12);
        this.dns_container = this.dns_column.newUIContainer("dns_container");
        this.dns_field = new TextField<>("dns_field", new PropertyModel<>(this, "dns_value"));
        this.dns_field.setLabel(Model.of("Subject Alternative Name"));
        this.dns_field.add(new ContainerFeedbackBehavior());
        this.dns_field.add(new CertificateDnsValidator());
        this.dns_container.add(this.dns_field);
        this.dns_container.newFeedback("dns_feedback", this.dns_field);

        this.row4.lastUIColumn("last_column");

        this.saveButton = new Button("saveButton") {
            @Override
            public void onSubmit() {
                saveButtonClick();
            }
        };

        this.form.add(this.saveButton);

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", CertificateBrowsePage.class);
        this.form.add(this.cancelButton);

        this.form.add(new ValidityValidator(this.valid_from_field, this.valid_until_field));
        this.form.add(new CertificateTlsValidator(this.ip_field, this.dns_field));
    }

    protected void saveButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        WebSession session = (WebSession) getWebSession();
        Optional<User> optionalUser = userRepository.findById(session.getUserId());
        User user = optionalUser.orElseThrow();

        try {
            long serial = System.currentTimeMillis();

            FileUpload csrFile = this.csr_value.get(0);
            String csrText = IOUtils.toString(csrFile.getInputStream(), StandardCharsets.UTF_8);
            PKCS10CertificationRequest csr = CsrDeserializer.convert(csrText);

            ApiConfiguration apiConfiguration = context.getBean(ApiConfiguration.class);
            CertificateService certificateService = context.getBean(CertificateService.class);

            CertificateTlsCsrRequest request = new CertificateTlsCsrRequest();
            request.setCsr(csr);
            request.setSerial(serial);
            request.setIp(Arrays.asList(StringUtils.split(this.ip_value, ',')));
            request.setDns(Arrays.asList(StringUtils.split(this.dns_value, ',')));
            request.setIssuerSerial(Long.valueOf(this.issuer_value.getId()));

            certificateService.certificateTlsGenerate(user, request, apiConfiguration.getCrl(), apiConfiguration.getAia());

            setResponsePage(CertificateBrowsePage.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}

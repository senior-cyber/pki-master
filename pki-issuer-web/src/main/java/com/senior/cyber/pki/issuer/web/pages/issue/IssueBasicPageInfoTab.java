package com.senior.cyber.pki.issuer.web.pages.issue;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.jackson.CsrDeserializer;
import com.senior.cyber.frmk.common.jpa.Sql;
import com.senior.cyber.frmk.common.wicket.Permission;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
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
import com.senior.cyber.pki.common.dto.CertificateCommonCsrRequest;
import com.senior.cyber.pki.dao.entity.Certificate_;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.issuer.web.configuration.ApiConfiguration;
import com.senior.cyber.pki.issuer.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.issuer.web.configuration.Mode;
import com.senior.cyber.pki.issuer.web.data.SingleChoiceProvider;
import com.senior.cyber.pki.issuer.web.factory.WebSession;
import com.senior.cyber.pki.issuer.web.pages.my.certificate.CertificateBrowsePage;
import com.senior.cyber.pki.issuer.web.validator.CsrValidator;
import com.senior.cyber.pki.issuer.web.validator.ValidityValidator;
import com.senior.cyber.pki.service.CertificateService;
import org.apache.commons.io.IOUtils;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;
import org.springframework.context.ApplicationContext;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class IssueBasicPageInfoTab extends ContentPanel {

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
    protected SingleChoiceProvider<String, String> issuer_provider;
    protected Option issuer_value;

    protected UIColumn valid_from_column;
    protected UIContainer valid_from_container;
    protected DateTextField valid_from_field;
    protected Date valid_from_value;

    protected UIColumn valid_until_column;
    protected UIContainer valid_until_container;
    protected DateTextField valid_until_field;
    protected Date valid_until_value;

    protected Button saveButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public IssueBasicPageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        WebSession session = (WebSession) getSession();
        this.issuer_provider = new SingleChoiceProvider<>(String.class, new StringConvertor(), String.class, new StringConvertor(), Sql.table(Certificate_.class), Sql.column(Certificate_.serial), Sql.column(Certificate_.commonName));
        this.issuer_provider.applyWhere("status", Sql.column(Certificate_.status) + " = '" + CertificateStatusEnum.Good.name() + "'");
        this.issuer_provider.applyWhere("type", Sql.column(Certificate_.type) + " = '" + CertificateTypeEnum.Issuer.name() + "'");
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Individual) {
//            this.issuer_provider.applyWhere("user", Sql.column(Certificate_.user) + " = " + session.getUserId());
        }

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

        this.saveButton = new Button("saveButton") {
            @Override
            public void onSubmit() {
                saveButtonClick();
            }
        };

        this.form.add(this.saveButton);
        WebSession session = (WebSession) getSession();
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (session.getRoles().hasRole(Role.NAME_ROOT) || session.getRoles().hasRole(Role.NAME_Page_MyCertificateGenerate_Issue_Action)) {
            } else {
                this.saveButton.setVisible(false);
            }
        }

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", CertificateBrowsePage.class);
        this.form.add(this.cancelButton);

        this.form.add(new ValidityValidator(this.valid_from_field, this.valid_until_field));
    }

    protected void saveButtonClick() {
        WebSession session = (WebSession) getSession();
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            Permission.tryAccess(session, Role.NAME_ROOT, Role.NAME_Page_MyCertificateGenerate_Issue_Action);
        }
        try {
            long serial = System.currentTimeMillis();

            FileUpload csrFile = this.csr_value.get(0);
            String csrText = IOUtils.toString(csrFile.getInputStream(), StandardCharsets.UTF_8);
            PKCS10CertificationRequest csr = CsrDeserializer.convert(csrText);

            ApiConfiguration apiConfiguration = context.getBean(ApiConfiguration.class);
            CertificateService certificateService = context.getBean(CertificateService.class);

            CertificateCommonCsrRequest request = new CertificateCommonCsrRequest();
            request.setCsr(csr);
            request.setSerial(serial);
            request.setIssuerSerial(Long.valueOf(this.issuer_value.getId()));

            certificateService.certificateCommonGenerate(request, apiConfiguration.getCrl(), apiConfiguration.getAia());

            setResponsePage(CertificateBrowsePage.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}

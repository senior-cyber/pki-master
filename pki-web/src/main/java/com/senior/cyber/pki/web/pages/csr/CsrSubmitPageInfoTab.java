package com.senior.cyber.pki.web.pages.csr;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.jpa.Sql;
import com.senior.cyber.frmk.common.wicket.Permission;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
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
import com.senior.cyber.frmk.common.x509.CertificateUtils;
import com.senior.cyber.frmk.common.x509.CsrUtils;
import com.senior.cyber.frmk.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.*;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.IntermediateStatusEnum;
import com.senior.cyber.pki.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.web.configuration.Mode;
import com.senior.cyber.pki.web.configuration.PkiApiConfiguration;
import com.senior.cyber.pki.web.data.SingleChoiceProvider;
import com.senior.cyber.pki.web.dto.*;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.pages.my.certificate.CertificateBrowsePage;
import com.senior.cyber.pki.web.repository.CertificateRepository;
import com.senior.cyber.pki.web.repository.IntermediateRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.pki.web.utility.CertificateUtility;
import com.senior.cyber.pki.web.utility.CertificationSignRequestUtility;
import com.senior.cyber.pki.web.validator.CertificateSanValidator;
import com.senior.cyber.pki.web.validator.CsrValidator;
import com.senior.cyber.pki.web.validator.ValidityValidator;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextArea;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.Days;
import org.joda.time.LocalDate;
import org.springframework.context.ApplicationContext;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;

public class CsrSubmitPageInfoTab extends ContentPanel {

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn csr_column;
    protected UIContainer csr_container;
    protected FileUploadField csr_field;
    protected List<FileUpload> csr_value;

    protected UIRow row2;

    protected UIColumn intermediate_column;
    protected UIContainer intermediate_container;
    protected Select2SingleChoice intermediate_field;
    protected SingleChoiceProvider<String, String> intermediate_provider;
    protected Option intermediate_value;

    protected UIColumn valid_from_column;
    protected UIContainer valid_from_container;
    protected DateTextField valid_from_field;
    protected Date valid_from_value;

    protected UIColumn valid_until_column;
    protected UIContainer valid_until_container;
    protected DateTextField valid_until_field;
    protected Date valid_until_value;

    protected UIRow row3;

    protected UIColumn san_column;
    protected UIContainer san_container;
    protected TextArea<String> san_field;
    protected String san_value;

    protected Button saveButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public CsrSubmitPageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        WebSession session = (WebSession) getSession();
        this.intermediate_provider = new SingleChoiceProvider<>(String.class, new StringConvertor(), String.class, new StringConvertor(), Sql.table(Intermediate_.class), Sql.column(Intermediate_.id), Sql.column(Intermediate_.commonName));
        this.intermediate_provider.applyWhere("status", Sql.column(Intermediate_.status) + " = '" + IntermediateStatusEnum.Good.name() + "'");
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Individual) {
            this.intermediate_provider.applyWhere("user", Sql.column(Intermediate_.user) + " = " + session.getUserId());
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

        this.intermediate_column = this.row2.newUIColumn("intermediate_column", Size.Four_4);
        this.intermediate_container = this.intermediate_column.newUIContainer("intermediate_container");
        this.intermediate_field = new Select2SingleChoice("intermediate_field", new PropertyModel<>(this, "intermediate_value"), this.intermediate_provider);
        this.intermediate_field.setLabel(Model.of("Intermediate"));
        this.intermediate_field.setRequired(true);
        this.intermediate_field.add(new ContainerFeedbackBehavior());
        this.intermediate_container.add(this.intermediate_field);
        this.intermediate_container.newFeedback("intermediate_feedback", this.intermediate_field);

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

        this.san_column = this.row3.newUIColumn("san_column", Size.Twelve_12);
        this.san_container = this.san_column.newUIContainer("san_container");
        this.san_field = new TextArea<>("san_field", new PropertyModel<>(this, "san_value"));
        this.san_field.setLabel(Model.of("Subject Alternative Name"));
        this.san_field.add(new ContainerFeedbackBehavior());
        this.san_field.add(new CertificateSanValidator());
        this.san_container.add(this.san_field);
        this.san_container.newFeedback("san_feedback", this.san_field);

        this.row3.lastUIColumn("last_column");

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

            PkiApiConfiguration pkiApiConfiguration = context.getBean(PkiApiConfiguration.class);
            IntermediateRepository intermediateRepository = context.getBean(IntermediateRepository.class);
            CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
            UserRepository userRepository = context.getBean(UserRepository.class);

            Optional<User> optionalUser = userRepository.findById(session.getUserId());
            User user = optionalUser.orElseThrow(() -> new WicketRuntimeException("user is not found"));

            Optional<Intermediate> optionalRoot = intermediateRepository.findById(this.intermediate_value.getId());
            Intermediate intermediate = optionalRoot.orElseThrow(() -> new WicketRuntimeException(""));

            FileUpload csrFile = this.csr_value.get(0);
            String csrText = IOUtils.toString(csrFile.getInputStream(), StandardCharsets.UTF_8);

            PKCS10CertificationRequest csr = CsrUtils.read(csrText);

            LocalDate validFrom = LocalDate.fromDateFields(this.valid_from_value);
            LocalDate validUntil = LocalDate.fromDateFields(this.valid_until_value);

            CertificateRequestDto requestDto = new CertificateRequestDto();
            requestDto.setBasicConstraints(false);
            requestDto.setCsr(csr);
            requestDto.setIssuerCertificate(CertificateUtils.read(intermediate.getCertificate()));
            requestDto.setIssuerPrivateKey(PrivateKeyUtils.read(intermediate.getPrivateKey()));
            requestDto.setDuration(Days.daysBetween(validFrom, validUntil).getDays());
            requestDto.setSerial(serial);

            requestDto.setBasicConstraintsCritical(true);
            requestDto.setKeyUsageCritical(true);

            requestDto.setSubjectAlternativeNameCritical(false);

            requestDto.setSubjectKeyIdentifierCritical(false);
            requestDto.setAuthorityKeyIdentifierCritical(false);
            requestDto.setAuthorityInfoAccessCritical(false);

            requestDto.setExtendedKeyUsageCritical(false);

            requestDto.setcRLDistributionPointsCritical(false);

            for (String httpAddress : pkiApiConfiguration.getAddress()) {
                requestDto.getCRLDistributionPoints().add(new GeneralNameDto(httpAddress + "/api/pki/crl/intermediate/" + intermediate.getSerial() + ".crl"));
                requestDto.getAuthorityInfoAccess().add(new GeneralNameDto(GeneralNameTypeEnum.OCSP, httpAddress + "/api/pki/ocsp/intermediate/" + intermediate.getSerial()));
                requestDto.getAuthorityInfoAccess().add(new GeneralNameDto(GeneralNameTypeEnum.CA, httpAddress + "/api/pki/intermediate/" + intermediate.getSerial() + ".der"));
            }

            String subjectAltNames = StringUtils.trimToEmpty(this.san_value);
            List<String> subjectAltName = new ArrayList<>();
            if (subjectAltNames != null && !"".equals(subjectAltNames)) {
                for (String temp : StringUtils.split(subjectAltNames, ",")) {
                    temp = StringUtils.trimToEmpty(temp);
                    if (!"".equals(temp)) {
                        if (!subjectAltName.contains("IP:" + temp) && !subjectAltName.contains("DNS:" + temp)) {
                            if (InetAddressValidator.getInstance().isValid(temp)) {
                                subjectAltName.add("IP:" + temp);
                                requestDto.getSubjectAlternativeName().add(new GeneralNameDto(GeneralNameTagEnum.IP, temp));
                            } else if (DomainValidator.getInstance().isValid(temp)) {
                                subjectAltName.add("DNS:" + temp);
                                requestDto.getSubjectAlternativeName().add(new GeneralNameDto(GeneralNameTagEnum.DNS, temp));
                            } else {
                                if (temp.matches("[A-Za-z0-9._-]+")) {
                                    subjectAltName.add("DNS:" + temp);
                                    requestDto.getSubjectAlternativeName().add(new GeneralNameDto(GeneralNameTagEnum.DNS, temp));
                                } else {
                                    if (temp.startsWith("*.")) {
                                        if (DomainValidator.getInstance().isValid(temp.substring(2))) {
                                            subjectAltName.add("DNS:" + temp);
                                            requestDto.getSubjectAlternativeName().add(new GeneralNameDto(GeneralNameTagEnum.DNS, temp));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            CsrDto csrDto = CertificationSignRequestUtility.readCsr(csr);

            X509Certificate x509Certificate = CertificateUtility.generate(requestDto);

            Certificate certificate = new Certificate();

            certificate.setSerial(serial);

            certificate.setLocalityName(csrDto.getLocalityName());
            certificate.setStateOrProvinceName(csrDto.getStateOrProvinceName());
            certificate.setCountryCode(csrDto.getCountryCode());
            certificate.setCommonName(csrDto.getCommonName());
            certificate.setOrganization(csrDto.getOrganization());
            certificate.setOrganizationalUnit(csrDto.getOrganizationalUnit());
            certificate.setEmailAddress(csrDto.getEmailAddress());
            certificate.setSan(this.san_value);

            certificate.setCertificate(CertificateUtils.write(x509Certificate));

            certificate.setValidFrom(validFrom.toDate());
            certificate.setValidUntil(validUntil.toDate());

            certificate.setStatus(CertificateStatusEnum.Good);

            certificate.setIntermediate(intermediate);

            certificate.setUser(user);
            certificateRepository.save(certificate);

            setResponsePage(CertificateBrowsePage.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}

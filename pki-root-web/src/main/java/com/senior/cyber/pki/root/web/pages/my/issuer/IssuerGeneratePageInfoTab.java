package com.senior.cyber.pki.root.web.pages.my.issuer;

import com.senior.cyber.frmk.common.base.WicketFactory;
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
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Option;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Select2SingleChoice;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.frmk.x509.*;
import com.senior.cyber.pki.dao.entity.*;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import com.senior.cyber.pki.dao.repository.IbanRepository;
import com.senior.cyber.pki.dao.repository.KeyRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.root.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.root.web.configuration.Mode;
import com.senior.cyber.pki.root.web.configuration.ApiConfiguration;
import com.senior.cyber.pki.root.web.data.SingleChoiceProvider;
import com.senior.cyber.pki.root.web.factory.WebSession;
import com.senior.cyber.pki.root.web.validator.IntermediateCommonNameValidator;
import com.senior.cyber.pki.root.web.validator.ValidityValidator;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.validation.validator.EmailAddressValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

public class IssuerGeneratePageInfoTab extends ContentPanel {

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn root_column;
    protected UIContainer root_container;
    protected Select2SingleChoice root_field;
    protected SingleChoiceProvider<String, String> root_provider;
    protected Option root_value;

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
    protected Select2SingleChoice country_field;
    protected SingleChoiceProvider<String, String> country_provider;
    protected Option country_value;

    protected UIRow row4;

    protected UIColumn valid_from_column;
    protected UIContainer valid_from_container;
    protected DateTextField valid_from_field;
    protected Date valid_from_value;

    protected UIColumn valid_until_column;
    protected UIContainer valid_until_container;
    protected DateTextField valid_until_field;
    protected Date valid_until_value;

    protected UIColumn email_address_column;
    protected UIContainer email_address_container;
    protected TextField<String> email_address_field;
    protected String email_address_value;

    protected Button saveButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public IssuerGeneratePageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        WebSession session = (WebSession) getSession();
        this.root_provider = new SingleChoiceProvider<>(String.class, new StringConvertor(), String.class, new StringConvertor(), Sql.table(Certificate_.class), Sql.column(Certificate_.id), Sql.column(Certificate_.commonName));
        this.root_provider.applyWhere("status", Sql.column(Certificate_.status) + " = '" + CertificateStatusEnum.Good.name() + "'");
        this.root_provider.applyWhere("type", Sql.column(Certificate_.type) + " IN ('" + CertificateTypeEnum.Root.name() + "', '" + CertificateTypeEnum.Issuer.name() + "')");
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Individual) {
            this.root_provider.applyWhere("user", Sql.column(Certificate_.user) + " = '" + session.getUserId() + "'");
        }
        this.country_provider = new SingleChoiceProvider<>(String.class, new StringConvertor(), String.class, new StringConvertor(), Sql.table(Iban_.class), Sql.column(Iban_.alpha2Code), Sql.column(Iban_.country));

        String uuid = getPage().getPageParameters().get("uuid").toString();
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
        IbanRepository ibanRepository = context.getBean(IbanRepository.class);

        Optional<Certificate> optionalCertificate = null;
        if (applicationConfiguration.getMode() == Mode.Individual) {
            UserRepository userRepository = context.getBean(UserRepository.class);
            Optional<User> optionalUser = userRepository.findById(session.getUserId());
            User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
            optionalCertificate = certificateRepository.findByIdAndUser(uuid, user);
        } else {
            optionalCertificate = certificateRepository.findById(uuid);
        }
        Certificate certificate = optionalCertificate.orElse(null);

        if (certificate != null) {
            Optional<Iban> optionalIban = ibanRepository.findByAlpha2Code(certificate.getCountryCode());
            Iban iban = optionalIban.orElseThrow(() -> new WicketRuntimeException(""));

            this.common_name_value = certificate.getCommonName();
            this.organization_value = certificate.getOrganization();
            this.organizational_unit_value = certificate.getOrganizationalUnit();
            this.locality_name_value = certificate.getLocalityName();
            this.state_or_province_name_value = certificate.getStateOrProvinceName();
            this.country_value = new Option(iban.getAlpha2Code(), iban.getCountry());
            this.email_address_value = certificate.getEmailAddress();
            if (certificate.getIssuerCertificate().getStatus() == CertificateStatusEnum.Good) {
                this.root_value = new Option(String.valueOf(certificate.getIssuerCertificate().getId()), certificate.getIssuerCertificate().getCommonName());
            }
        }

        LocalDate now = LocalDate.now();

        this.valid_from_value = now.toDate();
        this.valid_until_value = now.plusYears(3).toDate();
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.root_column = this.row1.newUIColumn("root_column", Size.Twelve_12);
        this.root_container = this.root_column.newUIContainer("root_container");
        this.root_field = new Select2SingleChoice("root_field", new PropertyModel<>(this, "root_value"), this.root_provider);
        this.root_field.setLabel(Model.of("Root"));
        this.root_field.setRequired(true);
        this.root_field.add(new ContainerFeedbackBehavior());
        this.root_container.add(this.root_field);
        this.root_container.newFeedback("root_feedback", this.root_field);

        this.row1.lastUIColumn("last_column");

        this.row2 = UIRow.newUIRow("row2", this.form);

        this.common_name_column = this.row2.newUIColumn("common_name_column", Size.Four_4);
        this.common_name_container = this.common_name_column.newUIContainer("common_name_container");
        this.common_name_field = new TextField<>("common_name_field", new PropertyModel<>(this, "common_name_value"));
        this.common_name_field.setLabel(Model.of("Common Name"));
        this.common_name_field.setRequired(true);
        this.common_name_field.add(new IntermediateCommonNameValidator());
        this.common_name_field.add(new ContainerFeedbackBehavior());
        this.common_name_container.add(this.common_name_field);
        this.common_name_container.newFeedback("common_name_feedback", this.common_name_field);

        this.organization_column = this.row2.newUIColumn("organization_column", Size.Four_4);
        this.organization_container = this.organization_column.newUIContainer("organization_container");
        this.organization_field = new TextField<>("organization_field", new PropertyModel<>(this, "organization_value"));
        this.organization_field.setLabel(Model.of("Organization"));
        this.organization_field.add(new ContainerFeedbackBehavior());
        this.organization_field.setRequired(true);
        this.organization_container.add(this.organization_field);
        this.organization_container.newFeedback("organization_feedback", this.organization_field);

        this.organizational_unit_column = this.row2.newUIColumn("organizational_unit_column", Size.Four_4);
        this.organizational_unit_container = this.organizational_unit_column.newUIContainer("organizational_unit_container");
        this.organizational_unit_field = new TextField<>("organizational_unit_field", new PropertyModel<>(this, "organizational_unit_value"));
        this.organizational_unit_field.setLabel(Model.of("Organizational Unit"));
        this.organizational_unit_field.add(new ContainerFeedbackBehavior());
        this.organizational_unit_container.add(this.organizational_unit_field);
        this.organizational_unit_container.newFeedback("organizational_unit_feedback", this.organizational_unit_field);

        this.row2.lastUIColumn("last_column");

        this.row3 = UIRow.newUIRow("row3", this.form);

        this.locality_name_column = this.row3.newUIColumn("locality_name_column", Size.Four_4);
        this.locality_name_container = this.locality_name_column.newUIContainer("locality_name_container");
        this.locality_name_field = new TextField<>("locality_name_field", new PropertyModel<>(this, "locality_name_value"));
        this.locality_name_field.setLabel(Model.of("Locality"));
        this.locality_name_field.add(new ContainerFeedbackBehavior());
        this.locality_name_container.add(this.locality_name_field);
        this.locality_name_container.newFeedback("locality_name_feedback", this.locality_name_field);

        this.state_or_province_name_column = this.row3.newUIColumn("state_or_province_name_column", Size.Four_4);
        this.state_or_province_name_container = this.state_or_province_name_column.newUIContainer("state_or_province_name_container");
        this.state_or_province_name_field = new TextField<>("state_or_province_name_field", new PropertyModel<>(this, "state_or_province_name_value"));
        this.state_or_province_name_field.setLabel(Model.of("State / Province"));
        this.state_or_province_name_field.add(new ContainerFeedbackBehavior());
        this.state_or_province_name_container.add(this.state_or_province_name_field);
        this.state_or_province_name_container.newFeedback("state_or_province_name_feedback", this.state_or_province_name_field);

        this.country_column = this.row3.newUIColumn("country_column", Size.Four_4);
        this.country_container = this.country_column.newUIContainer("country_container");
        this.country_field = new Select2SingleChoice("country_field", new PropertyModel<>(this, "country_value"), this.country_provider);
        this.country_field.setLabel(Model.of("Country"));
        this.country_field.setRequired(true);
        this.country_field.add(new ContainerFeedbackBehavior());
        this.country_container.add(this.country_field);
        this.country_container.newFeedback("country_feedback", this.country_field);

        this.row3.lastUIColumn("last_column");

        this.row4 = UIRow.newUIRow("row4", this.form);

        this.valid_from_column = this.row4.newUIColumn("valid_from_column", Size.Four_4);
        this.valid_from_container = this.valid_from_column.newUIContainer("valid_from_container");
        this.valid_from_field = new DateTextField("valid_from_field", new PropertyModel<>(this, "valid_from_value"));
        this.valid_from_field.setRequired(true);
        this.valid_from_field.setLabel(Model.of("Valid From"));
        this.valid_from_field.add(new ContainerFeedbackBehavior());
        this.valid_from_container.add(this.valid_from_field);
        this.valid_from_container.newFeedback("valid_from_feedback", this.valid_from_field);

        this.valid_until_column = this.row4.newUIColumn("valid_until_column", Size.Four_4);
        this.valid_until_container = this.valid_until_column.newUIContainer("valid_until_container");
        this.valid_until_field = new DateTextField("valid_until_field", new PropertyModel<>(this, "valid_until_value"));
        this.valid_until_field.setRequired(true);
        this.valid_until_field.setLabel(Model.of("Valid Until"));
        this.valid_until_field.add(new ContainerFeedbackBehavior());
        this.valid_until_container.add(this.valid_until_field);
        this.valid_until_container.newFeedback("valid_until_feedback", this.valid_until_field);

        this.email_address_column = this.row4.newUIColumn("email_address_column", Size.Four_4);
        this.email_address_container = this.email_address_column.newUIContainer("email_address_container");
        this.email_address_field = new TextField<>("email_address_field", new PropertyModel<>(this, "email_address_value"));
        this.email_address_field.setLabel(Model.of("Email Address"));
        this.email_address_field.add(new ContainerFeedbackBehavior());
        this.email_address_field.add(EmailAddressValidator.getInstance());
        this.email_address_container.add(this.email_address_field);
        this.email_address_container.newFeedback("email_address_feedback", this.email_address_field);

        this.row4.lastUIColumn("last_column");

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
            if (session.getRoles().hasRole(Role.NAME_ROOT) || session.getRoles().hasRole(Role.NAME_Page_MyIntermediateGenerate_Issue_Action)) {
            } else {
                this.saveButton.setVisible(false);
            }
        }

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", IssuerBrowsePage.class);
        this.form.add(this.cancelButton);

        this.form.add(new ValidityValidator(this.valid_from_field, this.valid_until_field));
    }

    protected void saveButtonClick() {
        WebSession session = (WebSession) getSession();
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            Permission.tryAccess(session, Role.NAME_ROOT, Role.NAME_Page_MyIntermediateGenerate_Issue_Action);
        }
        try {
            long serial = System.currentTimeMillis();

            ApiConfiguration apiConfiguration = context.getBean(ApiConfiguration.class);
            UserRepository userRepository = context.getBean(UserRepository.class);
            CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
            KeyRepository keyRepository = context.getBean(KeyRepository.class);

            Optional<User> optionalUser = userRepository.findById(session.getUserId());
            User user = optionalUser.orElseThrow(() -> new WicketRuntimeException("user is not found"));

            Optional<Certificate> optionalCertificate = certificateRepository.findBySerial(serial);
            if (optionalCertificate.isPresent()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not available");
            }

            Date now = LocalDate.now().toDate();

            Optional<Certificate> optionalIssuerCertificate = certificateRepository.findById(this.root_value.getId());
            Certificate issuerCertificate = optionalIssuerCertificate.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, this.root_value.getId() + " is not found"));
            if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                    (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Issuer) ||
                    issuerCertificate.getValidFrom().before(now) ||
                    issuerCertificate.getValidUntil().before(now)
            ) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, this.root_value.getId() + " is not valid");
            }

            // issuing
            KeyPair x509Key = com.senior.cyber.pki.common.x509.KeyUtils.generate();
            Key issuingKey = new Key();
            issuingKey.setPublicKey(x509Key.getPublic());
            issuingKey.setPrivateKey(x509Key.getPrivate());
            issuingKey.setSerial(System.currentTimeMillis());
            issuingKey.setCreatedDatetime(new Date());
            issuingKey.setUser(user);
            keyRepository.save(issuingKey);

            X500Name issuingSubject = SubjectUtils.generate(
                    this.country_value.getId(),
                    this.organization_value,
                    this.organizational_unit_value,
                    this.common_name_value,
                    this.locality_name_value,
                    this.state_or_province_name_value,
                    this.email_address_value
            );
            PKCS10CertificationRequest issuingCsr = CsrUtils.generate(new KeyPair(issuingKey.getPublicKey(), issuingKey.getPrivateKey()), issuingSubject);
            X509Certificate issuingCertificate = com.senior.cyber.pki.common.x509.IssuerUtils.generate(issuerCertificate.getCertificate(), issuerCertificate.getKey().getPrivateKey(), issuingCsr, apiConfiguration.getCrl(), apiConfiguration.getAia(), serial);
            Certificate issuing = new Certificate();
            issuing.setIssuerCertificate(issuerCertificate);
            issuing.setCountryCode(this.country_value.getId());
            issuing.setOrganization(this.organization_value);
            issuing.setOrganizationalUnit(this.organizational_unit_value);
            issuing.setCommonName(this.common_name_value);
            issuing.setLocalityName(this.locality_name_value);
            issuing.setStateOrProvinceName(this.state_or_province_name_value);
            issuing.setEmailAddress(this.email_address_value);
            issuing.setKey(issuingKey);
            issuing.setCertificate(issuingCertificate);
            issuing.setSerial(issuingCertificate.getSerialNumber().longValueExact());
            issuing.setCreatedDatetime(new Date());
            issuing.setValidFrom(issuingCertificate.getNotBefore());
            issuing.setValidUntil(issuingCertificate.getNotAfter());
            issuing.setStatus(CertificateStatusEnum.Good);
            issuing.setType(CertificateTypeEnum.Root);
            issuing.setUser(user);
            certificateRepository.save(issuing);

            // crl
            Key crlKey = null;
            {
                KeyPair x509 = com.senior.cyber.pki.common.x509.KeyUtils.generate(com.senior.cyber.pki.common.x509.KeyFormat.RSA);
                Key key = new Key();
                key.setPrivateKey(x509.getPrivate());
                key.setPublicKey(x509.getPublic());
                key.setSerial(System.currentTimeMillis() + 1);
                key.setCreatedDatetime(new Date());
                keyRepository.save(key);
                crlKey = key;
            }
            X500Name crlSubject = SubjectUtils.generate(
                    this.country_value.getId(),
                    this.organization_value,
                    this.organizational_unit_value,
                    this.common_name_value + " CRL",
                    this.locality_name_value,
                    this.state_or_province_name_value,
                    this.email_address_value
            );
            PKCS10CertificationRequest crlCsr = CsrUtils.generate(new KeyPair(crlKey.getPublicKey(), crlKey.getPrivateKey()), crlSubject);
            X509Certificate crlCertificate = com.senior.cyber.pki.common.x509.CrlUtils.generate(issuingCertificate, issuingKey.getPrivateKey(), crlCsr, System.currentTimeMillis() + 1);
            Certificate crl = new Certificate();
            crl.setIssuerCertificate(issuing);
            crl.setCountryCode(this.country_value.getId());
            crl.setOrganization(this.organization_value);
            crl.setOrganizationalUnit(this.organizational_unit_value);
            crl.setCommonName(this.common_name_value + " CRL");
            crl.setLocalityName(this.locality_name_value);
            crl.setStateOrProvinceName(this.state_or_province_name_value);
            crl.setEmailAddress(this.email_address_value);
            crl.setKey(crlKey);
            crl.setCertificate(crlCertificate);
            crl.setSerial(crlCertificate.getSerialNumber().longValueExact());
            crl.setCreatedDatetime(new Date());
            crl.setValidFrom(crlCertificate.getNotBefore());
            crl.setValidUntil(crlCertificate.getNotAfter());
            crl.setStatus(CertificateStatusEnum.Good);
            crl.setType(CertificateTypeEnum.Crl);
            crl.setUser(user);
            certificateRepository.save(crl);

            // ocsp
            Key ocspKey = null;
            {
                KeyPair x509 = com.senior.cyber.pki.common.x509.KeyUtils.generate(com.senior.cyber.pki.common.x509.KeyFormat.RSA);
                Key key = new Key();
                key.setPrivateKey(x509.getPrivate());
                key.setPublicKey(x509.getPublic());
                key.setSerial(System.currentTimeMillis() + 2);
                key.setCreatedDatetime(new Date());
                keyRepository.save(key);
                ocspKey = key;
            }
            X500Name ocspSubject = SubjectUtils.generate(
                    this.country_value.getId(),
                    this.organization_value,
                    this.organizational_unit_value,
                    this.common_name_value + " OCSP",
                    this.locality_name_value,
                    this.state_or_province_name_value,
                    this.email_address_value
            );
            PKCS10CertificationRequest ocspCsr = CsrUtils.generate(new KeyPair(ocspKey.getPublicKey(), ocspKey.getPrivateKey()), ocspSubject);
            X509Certificate ocspCertificate = com.senior.cyber.pki.common.x509.CrlUtils.generate(issuingCertificate, issuingKey.getPrivateKey(), ocspCsr, System.currentTimeMillis() + 2);
            Certificate ocsp = new Certificate();
            ocsp.setIssuerCertificate(issuing);
            ocsp.setCountryCode(this.country_value.getId());
            ocsp.setOrganization(this.organization_value);
            ocsp.setOrganizationalUnit(this.organizational_unit_value);
            ocsp.setCommonName(this.common_name_value + " OCSP");
            ocsp.setLocalityName(this.locality_name_value);
            ocsp.setStateOrProvinceName(this.state_or_province_name_value);
            ocsp.setEmailAddress(this.email_address_value);
            ocsp.setKey(ocspKey);
            ocsp.setCertificate(ocspCertificate);
            ocsp.setSerial(ocspCertificate.getSerialNumber().longValueExact());
            ocsp.setCreatedDatetime(new Date());
            ocsp.setValidFrom(ocspCertificate.getNotBefore());
            ocsp.setValidUntil(ocspCertificate.getNotAfter());
            ocsp.setStatus(CertificateStatusEnum.Good);
            ocsp.setType(CertificateTypeEnum.Ocsp);
            ocsp.setUser(null);
            certificateRepository.save(ocsp);

            issuing.setCrlCertificate(crl);
            issuing.setOcspCertificate(ocsp);
            certificateRepository.save(issuing);

            setResponsePage(IssuerBrowsePage.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}

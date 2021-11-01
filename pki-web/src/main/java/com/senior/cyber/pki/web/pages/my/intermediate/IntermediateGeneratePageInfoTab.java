package com.senior.cyber.pki.web.pages.my.intermediate;


import com.senior.cyber.frmk.common.wicket.markup.html.form.DateTextField;
import com.senior.cyber.pki.dao.entity.Iban;
import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.configuration.PkiApiConfiguration;
import com.senior.cyber.pki.web.data.SingleChoiceProvider;
import com.senior.cyber.pki.web.dto.CertificateRequestDto;
import com.senior.cyber.pki.web.dto.GeneralNameDto;
import com.senior.cyber.pki.web.dto.GeneralNameTypeEnum;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.repository.IbanRepository;
import com.senior.cyber.pki.web.repository.IntermediateRepository;
import com.senior.cyber.pki.web.repository.RootRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.pki.web.utility.CertificateUtility;
import com.senior.cyber.pki.web.utility.CertificationSignRequestUtility;
import com.senior.cyber.pki.web.utility.KeyPairUtility;
import com.senior.cyber.pki.web.utility.SubjectUtility;
import com.senior.cyber.pki.web.validator.IntermediateCommonNameValidator;
import com.senior.cyber.pki.web.validator.IntermediateOrganizationValidator;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.pki.CertificateUtils;
import com.senior.cyber.frmk.common.pki.PrivateKeyUtils;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Option;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Select2SingleChoice;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.pki.web.validator.ValidityValidator;
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
import org.joda.time.Days;
import org.joda.time.LocalDate;
import org.springframework.context.ApplicationContext;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

public class IntermediateGeneratePageInfoTab extends ContentPanel {

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn root_column;
    protected UIContainer root_container;
    protected Select2SingleChoice root_field;
    protected SingleChoiceProvider<Long, String> root_provider;
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

    public IntermediateGeneratePageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        WebSession session = (WebSession) getSession();
        this.root_provider = new SingleChoiceProvider<>(Long.class, new LongConvertor(), String.class, new StringConvertor(), "tbl_root", "root_id", "common_name");
        this.root_provider.applyWhere("status", "status = 'Good'");
        this.root_provider.applyWhere("user", "user_id = " + session.getUserId());
        this.country_provider = new SingleChoiceProvider<>(String.class, new StringConvertor(), String.class, new StringConvertor(), "tbl_iban", "alpha2_code", "country");

        long uuid = getPage().getPageParameters().get("uuid").toLong(-1);
        ApplicationContext context = WicketFactory.getApplicationContext();
        IntermediateRepository intermediateRepository = context.getBean(IntermediateRepository.class);
        UserRepository userRepository = context.getBean(UserRepository.class);
        IbanRepository ibanRepository = context.getBean(IbanRepository.class);

        Optional<User> optionalUser = userRepository.findById(session.getUserId());
        User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));

        Optional<Intermediate> optionalIntermediate = intermediateRepository.findByIdAndUser(uuid, user);
        Intermediate intermediate = optionalIntermediate.orElse(null);

        if (intermediate != null) {
            Optional<Iban> optionalIban = ibanRepository.findByAlpha2Code(intermediate.getCountryCode());
            Iban iban = optionalIban.orElseThrow(() -> new WicketRuntimeException(""));

            this.common_name_value = intermediate.getCommonName();
            this.organization_value = intermediate.getOrganization();
            this.organizational_unit_value = intermediate.getOrganizationalUnit();
            this.locality_name_value = intermediate.getLocalityName();
            this.state_or_province_name_value = intermediate.getStateOrProvinceName();
            this.country_value = new Option(iban.getAlpha2Code(), iban.getCountry());
            this.email_address_value = intermediate.getEmailAddress();
            if ("Good".equals(intermediate.getRoot().getStatus())) {
                this.root_value = new Option(String.valueOf(intermediate.getRoot().getId()), intermediate.getRoot().getCommonName());
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

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", IntermediateBrowsePage.class);
        this.form.add(this.cancelButton);

        this.form.add(new ValidityValidator(this.valid_from_field, this.valid_until_field));
    }

    protected void saveButtonClick() {
        try {
            long serial = System.currentTimeMillis();

            ApplicationContext context = WicketFactory.getApplicationContext();
            PkiApiConfiguration pkiApiConfiguration = context.getBean(PkiApiConfiguration.class);
            RootRepository rootRepository = context.getBean(RootRepository.class);
            IntermediateRepository intermediateRepository = context.getBean(IntermediateRepository.class);
            UserRepository userRepository = context.getBean(UserRepository.class);

            String httpAddress = pkiApiConfiguration.getAddress();

            WebSession session = (WebSession) getSession();

            Optional<User> optionalUser = userRepository.findById(session.getUserId());
            User user = optionalUser.orElseThrow(() -> new WicketRuntimeException("user is not found"));

            Optional<Root> optionalRoot = rootRepository.findById(Long.parseLong(this.root_value.getId()));
            Root root = optionalRoot.orElseThrow(() -> new WicketRuntimeException(""));

            KeyPair key = KeyPairUtility.generate();

            X500Name subject = SubjectUtility.generate(this.country_value.getId(), this.organization_value, this.organizational_unit_value, this.common_name_value, this.locality_name_value, this.state_or_province_name_value, this.email_address_value);

            PKCS10CertificationRequest csr = CertificationSignRequestUtility.generate(key.getPrivate(), key.getPublic(), subject);

            LocalDate validFrom = LocalDate.fromDateFields(this.valid_from_value);
            LocalDate validUntil = LocalDate.fromDateFields(this.valid_until_value);

            CertificateRequestDto requestDto = new CertificateRequestDto();
            requestDto.setBasicConstraints(true);
            requestDto.setCsr(csr);
            requestDto.setIssuerCertificate(CertificateUtils.read(root.getCertificate()));
            requestDto.setIssuerPrivateKey(PrivateKeyUtils.read(root.getPrivateKey()));
            requestDto.setDuration(Days.daysBetween(validFrom, validUntil).getDays());
            requestDto.setSerial(serial);

            requestDto.getCRLDistributionPoints().add(new GeneralNameDto(httpAddress + "/api/pki/crl/root/" + root.getSerial() + ".crl"));
            requestDto.getAuthorityInfoAccess().add(new GeneralNameDto(GeneralNameTypeEnum.OCSP, httpAddress + "/api/pki/ocsp/root/" + root.getSerial()));
            requestDto.getAuthorityInfoAccess().add(new GeneralNameDto(GeneralNameTypeEnum.CA, httpAddress + "/api/pki/root/" + root.getSerial() + ".der"));

            requestDto.setBasicConstraintsCritical(true);
            requestDto.setKeyUsageCritical(true);

            requestDto.setSubjectAlternativeNameCritical(false);

            requestDto.setSubjectKeyIdentifierCritical(false);
            requestDto.setAuthorityKeyIdentifierCritical(false);
            requestDto.setAuthorityInfoAccessCritical(false);

            requestDto.setExtendedKeyUsageCritical(false);

            requestDto.setcRLDistributionPointsCritical(false);

            X509Certificate certificate = CertificateUtility.generate(requestDto);

            Intermediate intermediate = new Intermediate();

            intermediate.setSerial(serial);

            intermediate.setLocalityName(this.locality_name_value);
            intermediate.setStateOrProvinceName(this.state_or_province_name_value);
            intermediate.setCountryCode(this.country_value.getId());
            intermediate.setCommonName(this.common_name_value);
            intermediate.setOrganization(this.organization_value);
            intermediate.setOrganizationalUnit(this.organizational_unit_value);
            intermediate.setEmailAddress(this.email_address_value);

            intermediate.setCertificate(CertificateUtils.write(certificate));
            intermediate.setPrivateKey(PrivateKeyUtils.write(key.getPrivate()));

            intermediate.setValidFrom(validFrom.toDate());
            intermediate.setValidUntil(validUntil.toDate());

            intermediate.setStatus("Good");

            intermediate.setRoot(root);

            intermediate.setUser(user);
            intermediateRepository.save(intermediate);

            setResponsePage(IntermediateBrowsePage.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}

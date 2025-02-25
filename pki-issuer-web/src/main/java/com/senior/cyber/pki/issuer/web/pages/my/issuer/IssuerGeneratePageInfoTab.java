//package com.senior.cyber.pki.issuer.web.pages.my.issuer;
//
//import com.senior.cyber.frmk.common.jakarta.persistence.Sql;
//import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.ContentPanel;
//import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
//import com.senior.cyber.frmk.common.wicket.layout.Size;
//import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
//import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
//import com.senior.cyber.frmk.common.wicket.layout.UIRow;
//import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
//import com.senior.cyber.pki.common.dto.IssuerGenerateRequest;
//import com.senior.cyber.pki.dao.entity.*;
//import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
//import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
//import com.senior.cyber.pki.dao.repository.CertificateRepository;
//import com.senior.cyber.pki.dao.repository.IbanRepository;
//import com.senior.cyber.pki.dao.repository.UserRepository;
//import com.senior.cyber.pki.issuer.web.configuration.ApiConfiguration;
//import com.senior.cyber.pki.issuer.web.factory.WebSession;
//import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
//import com.senior.cyber.pki.issuer.web.validator.ValidityValidator;
//import com.senior.cyber.pki.issuer.web.wicket.Option;
//import com.senior.cyber.pki.service.IssuerService;
//import org.apache.commons.lang3.StringUtils;
//import org.apache.commons.lang3.time.DateFormatUtils;
//import org.apache.wicket.MarkupContainer;
//import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
//import org.apache.wicket.markup.html.form.Button;
//import org.apache.wicket.markup.html.form.DropDownChoice;
//import org.apache.wicket.markup.html.form.Form;
//import org.apache.wicket.markup.html.form.TextField;
//import org.apache.wicket.markup.html.link.BookmarkablePageLink;
//import org.apache.wicket.model.Model;
//import org.apache.wicket.model.PropertyModel;
//import org.apache.wicket.request.mapper.parameter.PageParameters;
//import org.apache.wicket.validation.validator.EmailAddressValidator;
//import org.joda.time.LocalDate;
//import org.springframework.context.ApplicationContext;
//
//import java.util.*;
//
//public class IssuerGeneratePageInfoTab extends ContentPanel {
//
//    protected Certificate issuerCertificate;
//
//    protected Form<Void> form;
//
//    protected UIRow row1;
//
//    protected UIColumn issuer_column;
//    protected UIContainer issuer_container;
//    protected DropDownChoice<Option> issuer_field;
//    protected List<Option> issuer_provider;
//    protected Option issuer_value;
//
//    protected UIRow row2;
//
//    protected UIColumn common_name_column;
//    protected UIContainer common_name_container;
//    protected TextField<String> common_name_field;
//    protected String common_name_value;
//
//    protected UIColumn organization_column;
//    protected UIContainer organization_container;
//    protected TextField<String> organization_field;
//    protected String organization_value;
//
//    protected UIColumn organizational_unit_column;
//    protected UIContainer organizational_unit_container;
//    protected TextField<String> organizational_unit_field;
//    protected String organizational_unit_value;
//
//    protected UIRow row3;
//
//    protected UIColumn locality_name_column;
//    protected UIContainer locality_name_container;
//    protected TextField<String> locality_name_field;
//    protected String locality_name_value;
//
//    protected UIColumn state_or_province_name_column;
//    protected UIContainer state_or_province_name_container;
//    protected TextField<String> state_or_province_name_field;
//    protected String state_or_province_name_value;
//
//    protected UIColumn country_column;
//    protected UIContainer country_container;
//    protected DropDownChoice<Option> country_field;
//    protected List<Option> country_provider;
//    protected Option country_value;
//
//    protected UIRow row4;
//
//    protected UIColumn valid_from_column;
//    protected UIContainer valid_from_container;
//    protected TextField<String> valid_from_field;
//    protected String valid_from_value;
//
//    protected UIColumn valid_until_column;
//    protected UIContainer valid_until_container;
//    protected TextField<String> valid_until_field;
//    protected String valid_until_value;
//
//    protected UIColumn email_address_column;
//    protected UIContainer email_address_container;
//    protected TextField<String> email_address_field;
//    protected String email_address_value;
//
//    protected Button saveButton;
//    protected BookmarkablePageLink<Void> cancelButton;
//
//    public IssuerGeneratePageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
//        super(id, name, containerPanel, data);
//    }
//
//    @Override
//    protected void onInitData() {
//        WebSession session = (WebSession) getSession();
//        ApplicationContext context = WicketFactory.getApplicationContext();
//        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
//        IbanRepository ibanRepository = context.getBean(IbanRepository.class);
//
//        UserRepository userRepository = context.getBean(UserRepository.class);
//        Optional<User> optionalUser = userRepository.findById(session.getUserId());
//        User user = optionalUser.orElseThrow();
//
//        PageParameters parameters = getPage().getPageParameters();
//        long serial = parameters.get("serial").toLong(0L);
//        Optional<Certificate> optionalIssuerCertificate = certificateRepository.findBySerialAndUser(serial, user);
//        this.issuerCertificate = optionalIssuerCertificate.orElse(null);
//
////        List<String> types = new ArrayList<>();
////        types.add("'" + CertificateTypeEnum.Issuer.name() + "'");
////        types.add("'" + CertificateTypeEnum.Root.name() + "'");
////        this.issuer_provider = new Select2ChoiceProvider(Sql.table(Certificate_.class), Sql.column(Certificate_.serial), Sql.column(Certificate_.commonName));
////        this.issuer_provider.applyWhere("status", Sql.column(Certificate_.status) + " = '" + CertificateStatusEnum.Good.name() + "'");
////        this.issuer_provider.applyWhere("type", Sql.column(Certificate_.type) + " IN (" + StringUtils.join(types, ", ") + ")");
////        this.issuer_provider.applyWhere("user", Sql.column(Certificate_.user) + " = '" + session.getUserId() + "'");
////        this.country_provider = new Select2ChoiceProvider(Sql.table(Iban_.class), Sql.column(Iban_.alpha2Code), Sql.column(Iban_.country));
//
//        this.country_provider = new ArrayList<>();
//        for (Iban iban : ibanRepository.findAll()) {
//            this.country_provider.add(new Option(iban.getAlpha2Code(), iban.getCountry()));
//        }
//        this.issuer_provider = new ArrayList<>();
//        for (Certificate certificate : certificateRepository.findByUserAndStatusAndTypeIn(user, CertificateStatusEnum.Good, Arrays.asList(CertificateTypeEnum.Issuer, CertificateTypeEnum.Root))) {
//            this.issuer_provider.add(new Option(String.valueOf(certificate.getSerial()), certificate.getCommonName()));
//        }
//
//        if (this.issuerCertificate != null) {
//            this.issuer_value = new Option(String.valueOf(this.issuerCertificate.getSerial()), this.issuerCertificate.getCommonName());
//        }
//
//        LocalDate now = LocalDate.now();
//
//        this.valid_from_value = DateFormatUtils.format(now.toDate(), "dd/MM/yyyy");
//        this.valid_until_value = DateFormatUtils.format(now.plusYears(3).toDate(), "dd/MM/yyyy");
//    }
//
//    @Override
//    protected void onInitHtml(MarkupContainer body) {
//        this.form = new Form<>("form");
//        body.add(this.form);
//
//        this.row1 = UIRow.newUIRow("row1", this.form);
//
//        this.issuer_column = this.row1.newUIColumn("issuer_column", Size.Twelve_12);
//        this.issuer_container = this.issuer_column.newUIContainer("issuer_container");
//        this.issuer_field = new DropDownChoice<>("issuer_field", new PropertyModel<>(this, "issuer_value"), this.issuer_provider);
//        this.issuer_field.setLabel(Model.of("Root"));
//        this.issuer_field.setRequired(true);
//        this.issuer_field.add(new ContainerFeedbackBehavior());
//        this.issuer_container.add(this.issuer_field);
//        this.issuer_container.newFeedback("issuer_feedback", this.issuer_field);
//        if (this.issuerCertificate != null) {
//            this.issuer_field.setEnabled(false);
//        }
//
//        this.row1.lastUIColumn("last_column");
//
//        this.row2 = UIRow.newUIRow("row2", this.form);
//
//        this.common_name_column = this.row2.newUIColumn("common_name_column", Size.Four_4);
//        this.common_name_container = this.common_name_column.newUIContainer("common_name_container");
//        this.common_name_field = new TextField<>("common_name_field", new PropertyModel<>(this, "common_name_value"));
//        this.common_name_field.setLabel(Model.of("Common Name"));
//        this.common_name_field.setRequired(true);
//        this.common_name_field.add(new ContainerFeedbackBehavior());
//        this.common_name_container.add(this.common_name_field);
//        this.common_name_container.newFeedback("common_name_feedback", this.common_name_field);
//
//        this.organization_column = this.row2.newUIColumn("organization_column", Size.Four_4);
//        this.organization_container = this.organization_column.newUIContainer("organization_container");
//        this.organization_field = new TextField<>("organization_field", new PropertyModel<>(this, "organization_value"));
//        this.organization_field.setLabel(Model.of("Organization"));
//        this.organization_field.add(new ContainerFeedbackBehavior());
//        this.organization_field.setRequired(true);
//        this.organization_container.add(this.organization_field);
//        this.organization_container.newFeedback("organization_feedback", this.organization_field);
//
//        this.organizational_unit_column = this.row2.newUIColumn("organizational_unit_column", Size.Four_4);
//        this.organizational_unit_container = this.organizational_unit_column.newUIContainer("organizational_unit_container");
//        this.organizational_unit_field = new TextField<>("organizational_unit_field", new PropertyModel<>(this, "organizational_unit_value"));
//        this.organizational_unit_field.setLabel(Model.of("Organizational Unit"));
//        this.organizational_unit_field.add(new ContainerFeedbackBehavior());
//        this.organizational_unit_container.add(this.organizational_unit_field);
//        this.organizational_unit_container.newFeedback("organizational_unit_feedback", this.organizational_unit_field);
//
//        this.row2.lastUIColumn("last_column");
//
//        this.row3 = UIRow.newUIRow("row3", this.form);
//
//        this.locality_name_column = this.row3.newUIColumn("locality_name_column", Size.Four_4);
//        this.locality_name_container = this.locality_name_column.newUIContainer("locality_name_container");
//        this.locality_name_field = new TextField<>("locality_name_field", new PropertyModel<>(this, "locality_name_value"));
//        this.locality_name_field.setLabel(Model.of("Locality"));
//        this.locality_name_field.add(new ContainerFeedbackBehavior());
//        this.locality_name_container.add(this.locality_name_field);
//        this.locality_name_container.newFeedback("locality_name_feedback", this.locality_name_field);
//
//        this.state_or_province_name_column = this.row3.newUIColumn("state_or_province_name_column", Size.Four_4);
//        this.state_or_province_name_container = this.state_or_province_name_column.newUIContainer("state_or_province_name_container");
//        this.state_or_province_name_field = new TextField<>("state_or_province_name_field", new PropertyModel<>(this, "state_or_province_name_value"));
//        this.state_or_province_name_field.setLabel(Model.of("State / Province"));
//        this.state_or_province_name_field.add(new ContainerFeedbackBehavior());
//        this.state_or_province_name_container.add(this.state_or_province_name_field);
//        this.state_or_province_name_container.newFeedback("state_or_province_name_feedback", this.state_or_province_name_field);
//
//        this.country_column = this.row3.newUIColumn("country_column", Size.Four_4);
//        this.country_container = this.country_column.newUIContainer("country_container");
//        this.country_field = new DropDownChoice<>("country_field", new PropertyModel<>(this, "country_value"), this.country_provider);
//        this.country_field.setLabel(Model.of("Country"));
//        this.country_field.setRequired(true);
//        this.country_field.add(new ContainerFeedbackBehavior());
//        this.country_container.add(this.country_field);
//        this.country_container.newFeedback("country_feedback", this.country_field);
//
//        this.row3.lastUIColumn("last_column");
//
//        this.row4 = UIRow.newUIRow("row4", this.form);
//
//        this.valid_from_column = this.row4.newUIColumn("valid_from_column", Size.Four_4);
//        this.valid_from_container = this.valid_from_column.newUIContainer("valid_from_container");
//        this.valid_from_field = new TextField<>("valid_from_field", new PropertyModel<>(this, "valid_from_value"));
//        this.valid_from_field.setRequired(true);
//        this.valid_from_field.setLabel(Model.of("Valid From"));
//        this.valid_from_field.add(new ContainerFeedbackBehavior());
//        this.valid_from_container.add(this.valid_from_field);
//        this.valid_from_container.newFeedback("valid_from_feedback", this.valid_from_field);
//
//        this.valid_until_column = this.row4.newUIColumn("valid_until_column", Size.Four_4);
//        this.valid_until_container = this.valid_until_column.newUIContainer("valid_until_container");
//        this.valid_until_field = new TextField<>("valid_until_field", new PropertyModel<>(this, "valid_until_value"));
//        this.valid_until_field.setRequired(true);
//        this.valid_until_field.setLabel(Model.of("Valid Until"));
//        this.valid_until_field.add(new ContainerFeedbackBehavior());
//        this.valid_until_container.add(this.valid_until_field);
//        this.valid_until_container.newFeedback("valid_until_feedback", this.valid_until_field);
//
//        this.email_address_column = this.row4.newUIColumn("email_address_column", Size.Four_4);
//        this.email_address_container = this.email_address_column.newUIContainer("email_address_container");
//        this.email_address_field = new TextField<>("email_address_field", new PropertyModel<>(this, "email_address_value"));
//        this.email_address_field.setLabel(Model.of("Email Address"));
//        this.email_address_field.add(new ContainerFeedbackBehavior());
//        this.email_address_field.add(EmailAddressValidator.getInstance());
//        this.email_address_container.add(this.email_address_field);
//        this.email_address_container.newFeedback("email_address_feedback", this.email_address_field);
//
//        this.row4.lastUIColumn("last_column");
//
//        this.saveButton = new Button("saveButton") {
//            @Override
//            public void onSubmit() {
//                saveButtonClick();
//            }
//        };
//        this.form.add(this.saveButton);
//
//        this.cancelButton = new BookmarkablePageLink<>("cancelButton", IssuerBrowsePage.class);
//        this.form.add(this.cancelButton);
//
//        this.form.add(new ValidityValidator(this.valid_from_field, this.valid_until_field));
//    }
//
//    protected void saveButtonClick() {
//        ApplicationContext context = WicketFactory.getApplicationContext();
//        UserRepository userRepository = context.getBean(UserRepository.class);
//        WebSession session = (WebSession) getWebSession();
//        Optional<User> optionalUser = userRepository.findById(session.getUserId());
//        User user = optionalUser.orElseThrow();
//
//        try {
//            IssuerService issuerService = context.getBean(IssuerService.class);
//            ApiConfiguration apiConfiguration = context.getBean(ApiConfiguration.class);
//
//            IssuerGenerateRequest request = new IssuerGenerateRequest();
//
//            request.setSerial(System.currentTimeMillis());
//            request.setIssuerSerial(Long.valueOf(this.issuer_value.getIdValue()));
//            request.setLocality(this.locality_name_value);
//            request.setProvince(this.state_or_province_name_value);
//            request.setCountry(this.country_value.getIdValue());
//            request.setCommonName(this.common_name_value);
//            request.setOrganization(this.organization_value);
//            request.setOrganizationalUnit(this.organizational_unit_value);
//            request.setEmailAddress(this.email_address_value);
//
//            issuerService.issuerGenerate(user, request, apiConfiguration.getCrl(), apiConfiguration.getAia());
//
//            setResponsePage(IssuerBrowsePage.class);
//        } catch (Throwable e) {
//            e.printStackTrace();
//        }
//    }
//
//}
//

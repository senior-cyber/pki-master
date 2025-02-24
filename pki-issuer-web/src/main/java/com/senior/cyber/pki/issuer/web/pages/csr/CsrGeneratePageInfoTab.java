package com.senior.cyber.pki.issuer.web.pages.csr;

import com.senior.cyber.frmk.common.jackson.CsrSerializer;
import com.senior.cyber.frmk.common.jackson.PrivateKeySerializer;
import com.senior.cyber.frmk.common.jakarta.persistence.Sql;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.frmk.x509.CsrUtils;
import com.senior.cyber.frmk.x509.KeyUtils;
import com.senior.cyber.frmk.x509.SubjectUtils;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Iban;
import com.senior.cyber.pki.dao.entity.Iban_;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import com.senior.cyber.pki.dao.repository.IbanRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.factory.WebSession;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
import com.senior.cyber.pki.issuer.web.pages.my.certificate.CertificateBrowsePage;
import com.senior.cyber.pki.issuer.web.utility.MemoryResourceStream;
import com.senior.cyber.pki.issuer.web.wicket.Option;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
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
import org.apache.wicket.request.IRequestCycle;
import org.apache.wicket.request.handler.resource.ResourceStreamRequestHandler;
import org.apache.wicket.request.resource.ContentDisposition;
import org.apache.wicket.util.resource.IResourceStream;
import org.apache.wicket.validation.validator.EmailAddressValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.context.ApplicationContext;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class CsrGeneratePageInfoTab extends ContentPanel {

    protected Form<Void> form;

    protected UIRow row1;

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

    protected UIRow row2;

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
    protected DropDownChoice<Option> country_field;
    protected List<Option> country_provider;
    protected Option country_value;

    protected UIRow row3;

    protected UIColumn email_address_column;
    protected UIContainer email_address_container;
    protected TextField<String> email_address_field;
    protected String email_address_value;

    protected Button generateButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public CsrGeneratePageInfoTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        WebSession session = (WebSession) getSession();
        ApplicationContext applicationContext = WicketFactory.getApplicationContext();
        IbanRepository ibanRepository = applicationContext.getBean(IbanRepository.class);
        this.country_provider = new ArrayList<>();
        for (Iban iban : ibanRepository.findAll()) {
            this.country_provider.add(new Option(iban.getAlpha2Code(), iban.getCountry()));
        }

        ApplicationContext context = WicketFactory.getApplicationContext();

        String uuid = getPage().getPageParameters().get("uuid").toString();
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);

        UserRepository userRepository = context.getBean(UserRepository.class);
        Optional<User> optionalUser = userRepository.findById(session.getUserId());
        User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
        Optional<Certificate> optionalCertificate = certificateRepository.findByIdAndUser(uuid, user);
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
        }
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.common_name_column = this.row1.newUIColumn("common_name_column", Size.Four_4);
        this.common_name_container = this.common_name_column.newUIContainer("common_name_container");
        this.common_name_field = new TextField<>("common_name_field", new PropertyModel<>(this, "common_name_value"));
        this.common_name_field.setLabel(Model.of("Common Name"));
        this.common_name_field.setRequired(true);
        this.common_name_field.add(new ContainerFeedbackBehavior());
        this.common_name_container.add(this.common_name_field);
        this.common_name_container.newFeedback("common_name_feedback", this.common_name_field);

        this.organization_column = this.row1.newUIColumn("organization_column", Size.Four_4);
        this.organization_container = this.organization_column.newUIContainer("organization_container");
        this.organization_field = new TextField<>("organization_field", new PropertyModel<>(this, "organization_value"));
        this.organization_field.setLabel(Model.of("Organization"));
        this.organization_field.setRequired(true);
        this.organization_field.add(new ContainerFeedbackBehavior());
        this.organization_container.add(this.organization_field);
        this.organization_container.newFeedback("organization_feedback", this.organization_field);

        this.organizational_unit_column = this.row1.newUIColumn("organizational_unit_column", Size.Four_4);
        this.organizational_unit_container = this.organizational_unit_column.newUIContainer("organizational_unit_container");
        this.organizational_unit_field = new TextField<>("organizational_unit_field", new PropertyModel<>(this, "organizational_unit_value"));
        this.organizational_unit_field.setLabel(Model.of("Organizational Unit"));
        this.organizational_unit_field.add(new ContainerFeedbackBehavior());
        this.organizational_unit_container.add(this.organizational_unit_field);
        this.organizational_unit_container.newFeedback("organizational_unit_feedback", this.organizational_unit_field);

        this.row1.lastUIColumn("last_column");

        this.row2 = UIRow.newUIRow("row2", this.form);

        this.locality_name_column = this.row2.newUIColumn("locality_name_column", Size.Four_4);
        this.locality_name_container = this.locality_name_column.newUIContainer("locality_name_container");
        this.locality_name_field = new TextField<>("locality_name_field", new PropertyModel<>(this, "locality_name_value"));
        this.locality_name_field.setLabel(Model.of("Locality"));
        this.locality_name_field.setRequired(true);
        this.locality_name_field.add(new ContainerFeedbackBehavior());
        this.locality_name_container.add(this.locality_name_field);
        this.locality_name_container.newFeedback("locality_name_feedback", this.locality_name_field);

        this.state_or_province_name_column = this.row2.newUIColumn("state_or_province_name_column", Size.Four_4);
        this.state_or_province_name_container = this.state_or_province_name_column.newUIContainer("state_or_province_name_container");
        this.state_or_province_name_field = new TextField<>("state_or_province_name_field", new PropertyModel<>(this, "state_or_province_name_value"));
        this.state_or_province_name_field.setLabel(Model.of("State / Province"));
        this.state_or_province_name_field.add(new ContainerFeedbackBehavior());
        this.state_or_province_name_field.setRequired(true);
        this.state_or_province_name_container.add(this.state_or_province_name_field);
        this.state_or_province_name_container.newFeedback("state_or_province_name_feedback", this.state_or_province_name_field);

        this.country_column = this.row2.newUIColumn("country_column", Size.Four_4);
        this.country_container = this.country_column.newUIContainer("country_container");
        this.country_field = new DropDownChoice<>("country_field", new PropertyModel<>(this, "country_value"), this.country_provider);
        this.country_field.setLabel(Model.of("Country"));
        this.country_field.setRequired(true);
        this.country_field.add(new ContainerFeedbackBehavior());
        this.country_container.add(this.country_field);
        this.country_container.newFeedback("country_feedback", this.country_field);

        this.row2.lastUIColumn("last_column");

        this.row3 = UIRow.newUIRow("row3", this.form);

        this.email_address_column = this.row3.newUIColumn("email_address_column", Size.Four_4);
        this.email_address_container = this.email_address_column.newUIContainer("email_address_container");
        this.email_address_field = new TextField<>("email_address_field", new PropertyModel<>(this, "email_address_value"));
        this.email_address_field.setLabel(Model.of("Email Address"));
        this.email_address_field.add(EmailAddressValidator.getInstance());
        this.email_address_field.add(new ContainerFeedbackBehavior());
        this.email_address_container.add(this.email_address_field);
        this.email_address_container.newFeedback("email_address_feedback", this.email_address_field);

        this.row3.lastUIColumn("last_column");

        this.generateButton = new Button("generateButton") {
            @Override
            public void onSubmit() {
                generateButtonClick();
            }
        };
        this.form.add(this.generateButton);

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", CertificateBrowsePage.class);
        this.form.add(this.cancelButton);
    }

    protected void generateButtonClick() {
        try {
            KeyPair key = KeyUtils.generate();
            X500Name subject = SubjectUtils.generate(this.country_value.getIdValue(), this.organization_value, this.organizational_unit_value, this.common_name_value, this.locality_name_value, this.state_or_province_name_value, this.email_address_value);
            PKCS10CertificationRequest csr = CsrUtils.generate(key, subject);

            ByteArrayOutputStream data = new ByteArrayOutputStream();
            ZipArchiveOutputStream zipArchiveOutputStream = new ZipArchiveOutputStream(data);

            String name = "csr";

            {
                String csrText = CsrSerializer.convert(csr);
                ZipArchiveEntry caChainEntry = new ZipArchiveEntry(name + ".csr");
                caChainEntry.setSize(csrText.getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(caChainEntry);
                zipArchiveOutputStream.write(csrText.getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                String privateKey = PrivateKeySerializer.convert(key.getPrivate());
                ZipArchiveEntry privateKeyEntry = new ZipArchiveEntry(name + ".pem");
                privateKeyEntry.setSize(privateKey.getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(privateKeyEntry);
                zipArchiveOutputStream.write(privateKey.getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            zipArchiveOutputStream.close();

            IResourceStream resourceStream = new MemoryResourceStream("application/zip", data.toByteArray());
            getRequestCycle().scheduleRequestHandlerAfterCurrent(
                    new ResourceStreamRequestHandler(resourceStream) {
                        @Override
                        public void respond(IRequestCycle requestCycle) {
                            super.respond(requestCycle);
                        }
                    }.setFileName(name + ".zip")
                            .setContentDisposition(ContentDisposition.INLINE)
                            .setCacheDuration(Duration.ZERO));
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}

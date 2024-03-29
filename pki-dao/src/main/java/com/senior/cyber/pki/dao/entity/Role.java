package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.util.Map;

@Entity
@Table(name = "tbl_role")
@Getter
@Setter
public class Role implements Serializable {

    public static final String NAME_ROOT = "root";
    public static final String NAME_Page_MyProfile = "MyProfilePage";
    public static final String NAME_Page_RoleBrowse = "RoleBrowsePage";

    public static final String NAME_Page_MyCertificateBrowse = "MyCertificateBrowsePage";
    public static final String NAME_Page_MyCertificateBrowse_IssueNewCertificate_Action = "MyCertificateBrowsePageIssueNewCertificateAction";
    public static final String NAME_Page_MyCertificateBrowse_Copy_Action = "MyCertificateBrowsePageCopyAction";
    public static final String NAME_Page_MyCertificateBrowse_Revoke_Action = "MyCertificateBrowsePageRevokeAction";
    public static final String NAME_Page_MyCertificateBrowse_Download_Action = "MyCertificateBrowsePageDownloadAction";

    public static final String NAME_Page_MyCertificateGenerate = "MyCertificateGeneratePage";
    public static final String NAME_Page_MyCertificateGenerate_Issue_Action = "MyCertificateGeneratePageIssueAction";

    public static final String NAME_Page_CsrGenerate = "CsrGeneratePage";
    public static final String NAME_Page_CsrSubmit = "CsrSubmitPage";

    public static final String NAME_Page_MyCertificateRevoke = "MyCertificateRevokePage";
    public static final String NAME_Page_MyCertificateRevoke_Revoke_Action = "MyCertificateRevokePageRevokeAction";

    public static final String NAME_Page_MyRootBrowse = "MyRootBrowsePage";
    public static final String NAME_Page_MyRootBrowse_IssueNewRoot_Action = "MyRootBrowsePageIssueNewRootAction";
    public static final String NAME_Page_MyRootBrowse_Copy_Action = "MyRootBrowsePageCopyAction";
    public static final String NAME_Page_MyRootBrowse_Revoke_Action = "MyRootBrowsePageRevokeAction";
    public static final String NAME_Page_MyRootBrowse_Download_Action = "MyRootBrowsePageDownloadAction";

    public static final String NAME_Page_MyRootGenerate = "MyRootGeneratePage";
    public static final String NAME_Page_MyRootGenerate_Issue_Action = "MyRootGeneratePageIssueAction";

    public static final String NAME_Page_MyRootRevoke = "MyRootRevokePage";
    public static final String NAME_Page_MyRootRevoke_Revoke_Action = "MyRootRevokePageRevokeAction";

    public static final String NAME_Page_MyIntermediateBrowse = "MyIntermediateBrowsePage";
    public static final String NAME_Page_MyIntermediateBrowse_IssueNewIntermediate_Action = "MyIntermediateBrowsePageIssueNewIntermediateAction";
    public static final String NAME_Page_MyIntermediateBrowse_Copy_Action = "MyIntermediateBrowsePageCopyAction";
    public static final String NAME_Page_MyIntermediateBrowse_Revoke_Action = "MyIntermediateBrowsePageRevokeAction";
    public static final String NAME_Page_MyIntermediateBrowse_Download_Action = "MyIntermediateBrowsePageDownloadAction";

    public static final String NAME_Page_MyIntermediateGenerate = "MyIntermediateGeneratePage";
    public static final String NAME_Page_MyIntermediateGenerate_Issue_Action = "MyIntermediateGeneratePageIssueAction";

    public static final String NAME_Page_MyIntermediateRevoke = "MyIntermediateRevokePage";
    public static final String NAME_Page_MyIntermediateRevoke_Revoke_Action = "MyIntermediateRevokePageRevokeAction";

    public static final String NAME_Page_MyKey = "MyKeyPage";
    public static final String NAME_Page_MyKey_Create_Action = "MyKeyPageCreateAction";
    public static final String NAME_Page_MyKey_Delete_Action = "MyKeyPageDeleteAction";
    public static final String NAME_Page_MyKey_ShowSecret_Action = "MyKeyPageShowSecretAction";

    public static final String NAME_Page_SessionBrowse = "SessionBrowsePage";
    public static final String NAME_Page_SessionBrowse_Revoke_Action = "SessionBrowsePageRevokeAction";


    public static final String NAME_Page_GroupBrowse = "GroupBrowsePage";
    public static final String NAME_Page_GroupModify = "GroupModifyPage";
    public static final String NAME_Page_UserBrowse = "UserBrowsePage";
    public static final String NAME_Page_UserModify = "UserModifyPage";
    public static final String NAME_Page_UserSwitch = "UserSwitchPage";
    public static final String NAME_Page_UserExit = "UserExitPage";

    public static final String DESCRIPTION_ROOT = "could access everything";

    public static final String DESCRIPTION_Page_MyCertificateBrowse = "could access my certificate browse page";
    public static final String DESCRIPTION_Page_MyCertificateBrowse_IssueNewCertificate_Action = "could access issue new certificate button";
    public static final String DESCRIPTION_Page_MyCertificateBrowse_Copy_Action = "could access copy button";
    public static final String DESCRIPTION_Page_MyCertificateBrowse_Revoke_Action = "could access revoke button";
    public static final String DESCRIPTION_Page_MyCertificateBrowse_Download_Action = "could access download button";

    public static final String DESCRIPTION_Page_MyCertificateGenerate = "could access my certificate generate page";
    public static final String DESCRIPTION_Page_MyCertificateGenerate_Issue_Action = "could access issue button";

    public static final String DESCRIPTION_Page_MyKey = "could access my key page";
    public static final String DESCRIPTION_Page_MyKey_Create_Action = "could access create button";
    public static final String DESCRIPTION_Page_MyKey_Delete_Action = "could access delete button";
    public static final String DESCRIPTION_Page_MyKey_ShowSecret_Action = "could access show secret button";

    public static final String DESCRIPTION_Page_MyCertificateRevoke = "could access my certificate revoke page";
    public static final String DESCRIPTION_Page_MyCertificateRevoke_Revoke_Action = "could access revoke button";

    public static final String DESCRIPTION_Page_MyIntermediateBrowse = "could access my intermediate browse page";
    public static final String DESCRIPTION_Page_MyIntermediateBrowse_IssueNewIntermediate_Action = "could access issue new intermediate button";
    public static final String DESCRIPTION_Page_MyIntermediateBrowse_Copy_Action = "could access copy button";
    public static final String DESCRIPTION_Page_MyIntermediateBrowse_Revoke_Action = "could access revoke button";
    public static final String DESCRIPTION_Page_MyIntermediateBrowse_Download_Action = "could access download button";

    public static final String DESCRIPTION_Page_MyIntermediateGenerate = "could access my intermediate generate page";
    public static final String DESCRIPTION_Page_MyIntermediateGenerate_Issue_Action = "could access issue button";

    public static final String DESCRIPTION_Page_CsrGenerate = "could access csr generate page";

    public static final String DESCRIPTION_Page_CsrSubmit = "could access csr submit page";

    public static final String DESCRIPTION_Page_MyIntermediateRevoke = "could access my intermediate revoke page";
    public static final String DESCRIPTION_Page_MyIntermediateRevoke_Revoke_Action = "could access revoke button";

    public static final String DESCRIPTION_Page_MyRootBrowse = "could access my root browse page";
    public static final String DESCRIPTION_Page_MyRootBrowse_IssueNewRoot_Action = "could access issue new root button";
    public static final String DESCRIPTION_Page_MyRootBrowse_Copy_Action = "could access copy button";
    public static final String DESCRIPTION_Page_MyRootBrowse_Revoke_Action = "could access revoke button";
    public static final String DESCRIPTION_Page_MyRootBrowse_Download_Action = "could access download button";

    public static final String DESCRIPTION_Page_MyRootGenerate = "could access my root generate page";
    public static final String DESCRIPTION_Page_MyRootGenerate_Issue_Action = "could access issue button";

    public static final String DESCRIPTION_Page_MyRootRevoke = "could access my root revoke page";
    public static final String DESCRIPTION_Page_MyRootRevoke_Revoke_Action = "could access revoke button";

    public static final String DESCRIPTION_Page_SessionBrowse = "could access session browse page";
    public static final String DESCRIPTION_Page_SessionBrowse_Revoke_Action = "could access revoke button";

    public static final String DESCRIPTION_Page_MyProfile = "could access my profile page";
    public static final String DESCRIPTION_Page_RoleBrowse = "could access role browse page";
    public static final String DESCRIPTION_Page_GroupBrowse = "could access group browse page";
    public static final String DESCRIPTION_Page_GroupModify = "could access group update page";
    public static final String DESCRIPTION_Page_UserBrowse = "could access user browse page";
    public static final String DESCRIPTION_Page_UserModify = "could access user update page";
    public static final String DESCRIPTION_Page_UserSwitch = "could access user switch page";
    public static final String DESCRIPTION_Page_UserExit = "could access user exit page";

    @Id
    @UuidGenerator
    @Setter(AccessLevel.NONE)
    @Column(name = "role_id")
    private String id;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "enabled")
    private boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_group_role",
            joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "group_id", referencedColumnName = "group_id")

    )
    @MapKeyColumn(name = "group_role_id")
    private Map<String, Group> groups;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_user_role",
            joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id", referencedColumnName = "user_id")

    )
    @MapKeyColumn(name = "user_role_id")
    private Map<String, User> users;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_deny_role",
            joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    )
    @MapKeyColumn(name = "deny_role_id")
    private Map<String, User> denyUsers;

}

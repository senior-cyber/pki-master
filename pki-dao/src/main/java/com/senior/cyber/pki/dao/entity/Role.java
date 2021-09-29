package com.senior.cyber.pki.dao.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Map;

@Entity
@Table(name = "tbl_role")
public class Role implements Serializable {

    public static final String NAME_ROOT = "root";
    public static final String NAME_Page_MyProfile = "MyProfilePage";
    public static final String NAME_Page_RoleBrowse = "RoleBrowsePage";
    public static final String NAME_Page_MyCertificateBrowse = "MyCertificateBrowsePage";
    public static final String NAME_Page_MyCertificateGenerate = "MyCertificateGeneratePage";
    public static final String NAME_Page_MyCertificateRevoke = "MyCertificateRevokePage";
    public static final String NAME_Page_MyRootBrowse = "MyRootBrowsePage";
    public static final String NAME_Page_MyRootGenerate = "MyRootGeneratePage";
    public static final String NAME_Page_MyRootRevoke = "MyRootRevokePage";
    public static final String NAME_Page_MyIntermediateBrowse = "MyIntermediateBrowsePage";
    public static final String NAME_Page_MyKey = "MyKeyPage";
    public static final String NAME_Page_MyIntermediateGenerate = "MyIntermediateGeneratePage";
    public static final String NAME_Page_MyIntermediateRevoke = "MyIntermediateRevokePage";
    public static final String NAME_Page_GroupBrowse = "GroupBrowsePage";
    public static final String NAME_Page_SessionBrowse = "SessionBrowsePage";
    public static final String NAME_Page_GroupModify = "GroupModifyPage";
    public static final String NAME_Page_UserBrowse = "UserBrowsePage";
    public static final String NAME_Page_UserModify = "UserModifyPage";
    public static final String NAME_Page_UserSwitch = "UserSwitchPage";
    public static final String NAME_Page_UserExit = "UserExitPage";

    public static final String DESCRIPTION_ROOT = "could access everything";
    public static final String DESCRIPTION_Page_MyCertificateBrowse = "could access my certificate browse page";
    public static final String DESCRIPTION_Page_MyCertificateGenerate = "could access my certificate generate page";
    public static final String DESCRIPTION_Page_MyKey = "could access my key page";
    public static final String DESCRIPTION_Page_MyCertificateRevoke = "could access my certificate revoke page";
    public static final String DESCRIPTION_Page_MyIntermediateBrowse = "could access my intermediate browse page";
    public static final String DESCRIPTION_Page_MyIntermediateGenerate = "could access my intermediate generate page";
    public static final String DESCRIPTION_Page_MyIntermediateRevoke = "could access my intermediate revoke page";
    public static final String DESCRIPTION_Page_MyRootBrowse = "could access my root browse page";
    public static final String DESCRIPTION_Page_MyRootGenerate = "could access my root generate page";
    public static final String DESCRIPTION_Page_MyRootRevoke = "could access my root revoke page";
    public static final String DESCRIPTION_Page_MyProfile = "could access my profile page";
    public static final String DESCRIPTION_Page_RoleBrowse = "could access role browse page";
    public static final String DESCRIPTION_Page_GroupBrowse = "could access group browse page";
    public static final String DESCRIPTION_Page_SessionBrowse = "could access session browse page";
    public static final String DESCRIPTION_Page_GroupModify = "could access group update page";
    public static final String DESCRIPTION_Page_UserBrowse = "could access user browse page";
    public static final String DESCRIPTION_Page_UserModify = "could access user update page";
    public static final String DESCRIPTION_Page_UserSwitch = "could access user switch page";
    public static final String DESCRIPTION_Page_UserExit = "could access user exit page";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private Long id;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "enabled")
    private boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_group_role",
            joinColumns = @JoinColumn(name = "r_role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "r_group_id", referencedColumnName = "group_id")

    )
    @MapKeyColumn(name = "group_role_id")
    private Map<String, Group> groups;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_user_role",
            joinColumns = @JoinColumn(name = "r_role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "r_user_id", referencedColumnName = "user_id")

    )
    @MapKeyColumn(name = "user_role_id")
    private Map<String, User> users;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_deny_role",
            joinColumns = @JoinColumn(name = "r_role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "r_user_id", referencedColumnName = "user_id")
    )
    @MapKeyColumn(name = "deny_role_id")
    private Map<String, User> denyUsers;

    public Long getId() {
        return id;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Map<String, Group> getGroups() {
        return groups;
    }

    public void setGroups(Map<String, Group> groups) {
        this.groups = groups;
    }

    public Map<String, User> getUsers() {
        return users;
    }

    public void setUsers(Map<String, User> users) {
        this.users = users;
    }

    public Map<String, User> getDenyUsers() {
        return denyUsers;
    }

    public void setDenyUsers(Map<String, User> denyUsers) {
        this.denyUsers = denyUsers;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}

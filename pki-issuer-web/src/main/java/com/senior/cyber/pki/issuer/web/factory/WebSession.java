//package com.senior.cyber.pki.issuer.web.factory;
//
//import com.senior.cyber.pki.dao.entity.Role;
//import com.senior.cyber.pki.dao.entity.User;
//import com.senior.cyber.pki.issuer.web.utility.RoleUtility;
//import com.senior.cyber.pki.issuer.web.utility.UserUtility;
//import jakarta.servlet.http.HttpServletRequest;
//import lombok.Getter;
//import org.apache.wicket.authroles.authentication.AuthenticatedWebSession;
//import org.apache.wicket.authroles.authorization.strategies.role.Roles;
//import org.apache.wicket.request.Request;
//import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
//import org.jasypt.util.text.TextEncryptor;
//import org.springframework.context.ApplicationContext;
//import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
//
//import java.util.Collections;
//import java.util.LinkedList;
//import java.util.List;
//
//public class WebSession extends AuthenticatedWebSession {
//
//    @Getter
//    protected String userId;
//
//    protected List<String> queue;
//
//    protected Roles roles;
//
//    @Getter
//    protected String sessionId;
//
//    public WebSession(Request request) {
//        super(request);
//        HttpServletRequest req = (HttpServletRequest) request.getContainerRequest();
//        this.sessionId = req.getSession(true).getId();
//    }
//
//    @Override
//    public Roles getRoles() {
//        return this.roles;
//    }
//
//    @Override
//    protected boolean authenticate(String username, String password) {
//        ApplicationContext context = WicketFactory.getApplicationContext();
//
//        User user = UserUtility.authenticate(username, password);
//
//        if (user == null) {
//            return false;
//        }
//
//        NamedParameterJdbcTemplate named = context.getBean(NamedParameterJdbcTemplate.class);
//
//        this.queue = new LinkedList<>();
//        List<String> roles = RoleUtility.lookupRole(named, user.getId());
//        this.roles = new Roles();
//        this.roles.addAll(roles);
//        this.userId = user.getId();
//
//        return true;
//    }
//
//    public String getUserId() {
//        return userId;
//    }
//
//    public void switchUser(String userId) {
//        this.queue.add(this.userId);
//        this.userId = userId;
//
//        ApplicationContext context = WicketFactory.getApplicationContext();
//        NamedParameterJdbcTemplate named = context.getBean(NamedParameterJdbcTemplate.class);
//
//        List<String> roles = RoleUtility.lookupRole(named, this.userId);
//
//        Roles r = new Roles();
//        r.addAll(roles);
//        if (!queue.isEmpty()) {
//            r.add(Role.NAME_Page_UserSwitch);
//            r.add(Role.NAME_Page_UserExit);
//        }
//
//        this.roles = r;
//    }
//
//    public String getLoginUserId() {
//        if (this.queue == null || this.queue.isEmpty()) {
//            return this.userId;
//        } else {
//            return this.queue.get(0);
//        }
//    }
//
//    public void exitCurrent() {
//        this.userId = this.queue.remove(this.queue.size() - 1);
//
//        ApplicationContext context = WicketFactory.getApplicationContext();
//        NamedParameterJdbcTemplate named = context.getBean(NamedParameterJdbcTemplate.class);
//
//        List<String> roles = RoleUtility.lookupRole(named, this.userId);
//
//        Roles r = new Roles();
//        r.addAll(roles);
//        if (!queue.isEmpty()) {
//            r.add(Role.NAME_Page_UserSwitch);
//            r.add(Role.NAME_Page_UserExit);
//        }
//
//        this.roles = r;
//    }
//
//    public List<String> getQueue() {
//        return Collections.unmodifiableList(queue);
//    }
//
//}

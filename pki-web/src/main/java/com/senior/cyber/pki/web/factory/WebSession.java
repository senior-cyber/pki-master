package com.senior.cyber.pki.web.factory;

import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.Session;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.repository.HSessionRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.pki.web.utility.RoleUtility;
import com.senior.cyber.pki.web.utility.UserUtility;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.wicket.authroles.authentication.AuthenticatedWebSession;
import org.apache.wicket.authroles.authorization.strategies.role.Roles;
import org.apache.wicket.request.Request;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.util.text.TextEncryptor;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

public class WebSession extends AuthenticatedWebSession {

    protected Long userId;

    protected String pwd;

    protected List<Long> queue;

    protected Roles roles;

    protected String sessionId;

    public WebSession(Request request) {
        super(request);
        HttpServletRequest req = (HttpServletRequest) request.getContainerRequest();
        this.sessionId = req.getSession(true).getId();
        ApplicationContext context = WicketFactory.getApplicationContext();
        NamedParameterJdbcTemplate named = context.getBean(NamedParameterJdbcTemplate.class);
        UserRepository userRepository = context.getBean(UserRepository.class);
        HSessionRepository HSessionRepository = context.getBean(HSessionRepository.class);

        Optional<Session> optionalSession = HSessionRepository.findBySessionId(this.sessionId);
        Session session = optionalSession.orElse(null);
        if (session != null && session.getLogin() != null && !"".equals(session.getLogin())) {
            Optional<User> optionalUser = userRepository.findByLogin(session.getLogin());
            User user = optionalUser.orElse(null);
            if (user != null) {
                this.queue = new LinkedList<>();
                this.userId = user.getId();
                List<String> roles = RoleUtility.lookupRole(named, user.getId());
                this.roles = new Roles();
                this.roles.addAll(roles);
                signIn(true);
            }
        }
    }

    @Override
    public Roles getRoles() {
        return this.roles;
    }

    @Override
    protected boolean authenticate(String username, String password) {
        ApplicationContext context = WicketFactory.getApplicationContext();

        User user = UserUtility.authenticate(username, password);

        if (user == null) {
            return false;
        }

        NamedParameterJdbcTemplate named = context.getBean(NamedParameterJdbcTemplate.class);
        HSessionRepository hSessionRepository = context.getBean(HSessionRepository.class);
        TextEncryptor textEncryptor = context.getBean(TextEncryptor.class);

        this.queue = new LinkedList<>();
        List<String> roles = RoleUtility.lookupRole(named, user.getId());
        this.roles = new Roles();
        this.roles.addAll(roles);
        this.userId = user.getId();
        this.pwd = textEncryptor.encrypt(password);

        Optional<Session> optionalSession = hSessionRepository.findBySessionId(this.sessionId);
        Session session = optionalSession.orElse(null);
        if (session != null) {
            session.setLogin(user.getLogin());
            hSessionRepository.save(session);
        }
        return true;
    }

    public Long getUserId() {
        return userId;
    }

    public void switchUser(long userId) {
        this.queue.add(this.userId);
        this.userId = userId;

        ApplicationContext context = WicketFactory.getApplicationContext();
        NamedParameterJdbcTemplate named = context.getBean(NamedParameterJdbcTemplate.class);

        List<String> roles = RoleUtility.lookupRole(named, this.userId);

        Roles r = new Roles();
        r.addAll(roles);
        if (!queue.isEmpty()) {
            r.add(Role.NAME_Page_UserSwitch);
            r.add(Role.NAME_Page_UserExit);
        }

        this.roles = r;
    }

    public long getLoginUserId() {
        if (this.queue == null || this.queue.isEmpty()) {
            return this.userId;
        } else {
            return this.queue.get(0);
        }
    }

    public void exitCurrent() {
        this.userId = this.queue.remove(this.queue.size() - 1);

        ApplicationContext context = WicketFactory.getApplicationContext();
        NamedParameterJdbcTemplate named = context.getBean(NamedParameterJdbcTemplate.class);

        List<String> roles = RoleUtility.lookupRole(named, this.userId);

        Roles r = new Roles();
        r.addAll(roles);
        if (!queue.isEmpty()) {
            r.add(Role.NAME_Page_UserSwitch);
            r.add(Role.NAME_Page_UserExit);
        }

        this.roles = r;
    }

    public List<Long> getQueue() {
        return Collections.unmodifiableList(queue);
    }

    public String getPwd() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        TextEncryptor textEncryptor = context.getBean(TextEncryptor.class);
        try {
            return textEncryptor.decrypt(this.pwd);
        } catch (EncryptionOperationNotPossibleException e) {
            return null;
        }
    }

}

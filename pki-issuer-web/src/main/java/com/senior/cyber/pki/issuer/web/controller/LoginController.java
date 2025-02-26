package com.senior.cyber.pki.issuer.web.controller;

import com.senior.cyber.pki.issuer.web.model.LoginForm;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@SessionAttributes("loginForm")
@RequiredArgsConstructor
public class LoginController {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginController.class);

//    private final SurveyService surveyService;

    @RequestMapping(path = {"/login"}, method = RequestMethod.GET)
    public String doGet(Model model) {
        if (!model.containsAttribute("loginForm")) {
            model.addAttribute("loginForm", new LoginForm());
        }
        return "login";
    }

    @RequestMapping(path = {"/login"}, method = RequestMethod.POST)
    public String doPost(@ModelAttribute("loginForm") LoginForm loginForm,
                         HttpServletRequest request,
                         BindingResult bindingResult,
                         RedirectAttributes redirectAttributes) {
        if (loginForm.getLogin() == null || loginForm.getLogin().isEmpty()) {
            bindingResult.rejectValue("login", "login.required");
        }
        if (loginForm.getPassword() == null || loginForm.getPassword().isEmpty()) {
            bindingResult.rejectValue("password", "password.required");
        }

        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("loginForm", loginForm); // Add the form with errors
            redirectAttributes.addFlashAttribute(BindingResult.class.getName() + ".loginForm", bindingResult); // Add the BindingResult
            return "redirect:/login";
        } else {
            redirectAttributes.addFlashAttribute("loginForm", new LoginForm()); // Add the form with errors
            return "redirect:/login";
        }
    }

}

package com.fptaptech.auth.web;

import com.fptaptech.auth.security.CustomUserDetails;
import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.TotpSecret;
import com.fptaptech.auth.user.TotpSecretRepository;
import com.fptaptech.auth.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Optional;

@Controller
public class HomeController {

    private final UserService userService;
    private final TotpSecretRepository totpSecretRepository;

    public HomeController(UserService userService, TotpSecretRepository totpSecretRepository) {
        this.userService = userService;
        this.totpSecretRepository = totpSecretRepository;
    }

    @GetMapping("/")
    public String home(@AuthenticationPrincipal CustomUserDetails userDetails, Model model) {
        if (userDetails == null) {
            return "redirect:/login";
        }

        AppUser user = userService.findById(userDetails.getId()).orElse(userDetails.getUser());
        Optional<TotpSecret> optSecret = totpSecretRepository.findByUserId(user.getId());
        boolean totpEnabled = optSecret.isPresent() && optSecret.get().isEnabled();

        model.addAttribute("currentUser", user);
        model.addAttribute("totpEnabled", totpEnabled);
        return "welcome";
    }
}

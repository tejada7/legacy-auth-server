package com.ftm.oauthserver.endpoints;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class UserInfo {

    @GetMapping(value = "/oauth/userinfo")
    public Map<String, Object> user(@AuthenticationPrincipal Principal principal) {
        if (principal != null) {
            return Map.of("name", principal.getName(), "authorities",
                    SecurityContextHolder.getContext().getAuthentication().getAuthorities());
        }
        return null;
    }
}
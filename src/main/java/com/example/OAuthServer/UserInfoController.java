package com.example.OAuthServer;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserInfoController {

    @GetMapping("/userinfo")
    public Map<String, Object> userInfo(@AuthenticationPrincipal OidcUser oidcUser) {
        System.out.println("UserInfo endpoint hit");
        return oidcUser.getClaims();
    }
}


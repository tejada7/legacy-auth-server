package com.ftm.oauthserver.endpoints;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwkController {

    private final JWKSet jwkSet;

    public JwkController(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @GetMapping(value = "/oauth2/keys", produces = "application/json; charset=UTF-8")
    public String keys() {
        return this.jwkSet.toString();
    }
}
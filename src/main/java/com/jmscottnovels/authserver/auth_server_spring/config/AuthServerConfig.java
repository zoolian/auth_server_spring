package com.jmscottnovels.authserver.auth_server_spring.config;

import com.jmscottnovels.authserver.auth_server_spring.config.keys.KeyManager;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.UUID;

@Configuration
public class AuthServerConfig {

    private final KeyManager keyManager;

    public AuthServerConfig(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // TODO: is this automatic in auth server 1.x?
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // this is to test the forum client. move to db
        RegisteredClient client1 = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("forumClientID")
                .clientSecret("myClientSecret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .scope(OidcScopes.OPENID)
                .redirectUri("http://localhost:3002/login/oauth2/code/forum-client-oidc")
                .redirectUri("http://localhost:3002/authorized")
                .build();

        // TODO: move to JdbcRegisteredClientRepository()
        return new InMemoryRegisteredClientRepository(client1);
    }


    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://authserver:9000")   // separate hostname to avoid session cookie overwrites
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet set = new JWKSet(keyManager.rsaKey());
        return ((jwkSelector, securityContext) -> jwkSelector.select(set));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}

package com.example.oidc_client.config;

import com.example.oidc_client.service.TokenCleanupService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import com.example.oidc_client.service.InitialLoginTokenStorageService;

import java.util.HashSet;
import java.util.Set;

@Configuration
public class SecurityConfig {

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> customOidcUserService() {
        return userRequest -> {
            Set<GrantedAuthority> authorities = new HashSet<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

            return new DefaultOidcUser(
                    authorities,
                    userRequest.getIdToken(),
                    "sub"
            );
        };
    }

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        DefaultOAuth2AuthorizationRequestResolver defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization"
                );

        return new OAuth2AuthorizationRequestResolver() {

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                OAuth2AuthorizationRequest authorizationRequest =
                        defaultResolver.resolve(request);

                return customizeAuthorizationRequest(authorizationRequest);
            }

            @Override
            public OAuth2AuthorizationRequest resolve(
                    HttpServletRequest request,
                    String clientRegistrationId
            ) {
                OAuth2AuthorizationRequest authorizationRequest =
                        defaultResolver.resolve(request, clientRegistrationId);

                return customizeAuthorizationRequest(authorizationRequest);
            }

            private OAuth2AuthorizationRequest customizeAuthorizationRequest(
                    OAuth2AuthorizationRequest authorizationRequest
            ) {
                if (authorizationRequest == null) {
                    return null;
                }

                OAuth2AuthorizationRequest.Builder builder =
                        OAuth2AuthorizationRequest.from(authorizationRequest);

                OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder);

                return builder.build();
            }
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            OAuth2UserService<OidcUserRequest, OidcUser> customOidcUserService,
            OAuth2AuthorizationRequestResolver authorizationRequestResolver,
            AccessTokenAutoRefreshFilter accessTokenAutoRefreshFilter,
            TokenCleanupService tokenCleanupService,
            InitialLoginTokenStorageService initialLoginTokenStorageService
    ) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/error",
                                "/restore-session",
                                "/login"
                        ).permitAll()
                        .requestMatchers(PathRequest.toH2Console()).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler((request, response, authentication) -> {
                                initialLoginTokenStorageService.saveAfterLogin(authentication, request);
                                response.sendRedirect("/profile");
                                })
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(
                                        authorizationRequestResolver
                                )
                        )
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(customOidcUserService)
                        )
                        .failureHandler((request, response, exception) -> {
                            System.out.println("===== OAUTH2 LOGIN ERROR =====");
                            System.out.println(
                                    "Exception class: "
                                            + exception.getClass().getName()
                            );
                            System.out.println(
                                    "Exception message: "
                                            + exception.getMessage()
                            );

                            if (exception.getCause() != null) {
                                System.out.println(
                                        "Cause class: "
                                                + exception.getCause()
                                                .getClass()
                                                .getName()
                                );
                                System.out.println(
                                        "Cause message: "
                                                + exception.getCause()
                                                .getMessage()
                                );
                            }

                            System.out.println("==============================");

                            response.sendRedirect("/");
                        })
                )
                .logout(logout -> logout
                        .logoutSuccessHandler((request, response, authentication) -> {
                            tokenCleanupService.clearDefaultAuthorization(request);
                            response.sendRedirect("/");
                        })
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                )
                .addFilterAfter(
                        accessTokenAutoRefreshFilter,
                        AnonymousAuthenticationFilter.class
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(PathRequest.toH2Console())
                )
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())
                )
                .build();
    }
}
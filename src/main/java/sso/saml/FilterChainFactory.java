package sso.saml;

import static sso.saml.HandlerFactory.authenticationFailureHandler;
import static sso.saml.HandlerFactory.logoutHandler;
import static sso.saml.HandlerFactory.successLogoutHandler;
import static sso.saml.HandlerFactory.successRedirectHandler;
import static sso.saml.ProfileFactory.defaultWebSSOProfileOptions;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public class FilterChainFactory {

    @Bean
    public static SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    @Bean
    public static SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[]{logoutHandler()},
                new LogoutHandler[]{logoutHandler()});
    }

    @Bean
    public static SAMLProcessingFilter samlWebSSOProcessingFilter(AuthenticationManager authenticationManager) throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager);
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOProcessingFilter;
    }

    @Bean
    public static SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter(AuthenticationManager authenticationManager) throws Exception {
        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager);
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOHoKProcessingFilter;
    }

    @Bean
    public static MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }
    
    @Bean
    public static SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
    }

    @Bean
    public static SAMLDiscovery samlIDPDiscovery() {
        SAMLDiscovery idpDiscovery = new SAMLDiscovery();
        idpDiscovery.setIdpSelectionPath("/saml/idpSelection");
        return idpDiscovery;
    }
}

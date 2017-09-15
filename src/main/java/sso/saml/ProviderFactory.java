package sso.saml;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.SAMLAuthenticationProvider;

public class ProviderFactory {

    // SAML Authentication Provider responsible for validating of received SAML messages
    @Bean
    public static SAMLAuthenticationProvider getSAMLAuthenticationProvider(SAMLUserServiceImpl samlUserServiceImpl) {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails(samlUserServiceImpl);
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }
}

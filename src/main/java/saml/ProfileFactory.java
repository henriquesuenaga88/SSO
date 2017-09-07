package saml;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

public class ProfileFactory {

    @Bean
    public static WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }
    
}

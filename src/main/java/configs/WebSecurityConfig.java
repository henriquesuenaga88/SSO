package configs;

import static db.DataSourceFactory.getOracleDataSource;
import static saml.ProviderFactory.getSAMLAuthenticationProvider;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.w3c.dom.Document;

import saml.FilterChainFactory;
import saml.SAMLUserServiceImpl;
import db.DataBaseUserService;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${openldap.url}")
    private String ldapUrl;

    @Value("${openldap.usernameDN}")
    private String ldapUsernameDN;

    @Value("${openldap.password}")
    private String ldapPassword;
	
    @Autowired
    private DataBaseUserService dataBaseUserService;
    
    @Autowired
    private SAMLUserServiceImpl samlUserServiceImpl;
	
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home")
                .hasRole("USER")
//                .permitAll().anyRequest().authenticated()
                .and()
            .authorizeRequests()
            	.antMatchers("/", "/home", "/hello")
            	.hasRole("ADMIN")
            	.and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .permitAll();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//        	.inMemoryAuthentication()
//        	.withUser("user").password("user").roles("USER")
//        	.and()
//        	.withUser("admin").password("admin").roles("ADMIN");
    	
    	auth.jdbcAuthentication().dataSource(getOracleDataSource())
    		.withDefaultSchema()
    		.withUser("admin").password("etrust").roles("ADMIN")
    		.and()
    		.withUser("user").password("snow").roles("USER");
    }

    @Autowired
    public void configureAuthSource(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .userDetailsService(dataBaseUserService)
            .passwordEncoder(new BCryptPasswordEncoder());

        auth.ldapAuthentication()
            .userDnPatterns("uid={0},ou=people")
            .groupSearchBase("ou=groups")
            .contextSource()
            .url(ldapUrl)
            .managerDn(ldapUsernameDN)
            .managerPassword(ldapPassword);

        auth.authenticationProvider(getSAMLAuthenticationProvider(samlUserServiceImpl));
    }

    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
        		FilterChainFactory.samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
        		FilterChainFactory.samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
        		FilterChainFactory.metadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
        		FilterChainFactory.samlWebSSOProcessingFilter(authenticationManager())));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
        		FilterChainFactory.samlWebSSOHoKProcessingFilter(authenticationManager())));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
        		FilterChainFactory.samlLogoutProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
        		FilterChainFactory.samlIDPDiscovery()));
        return new FilterChainProxy(chains);
    }
    


    
    
    @Bean
    @Qualifier("idp-ssocircle")
    public ExtendedMetadataDelegate ssoCircleExtendedMetadataProvider()
            throws MetadataProviderException {


        AbstractMetadataProvider provider = new AbstractMetadataProvider() {
            @Override
            protected XMLObject doGetMetadata() throws MetadataProviderException {
                DefaultResourceLoader loader = new DefaultResourceLoader();
                Resource storeFile = loader.getResource("classPath:/saml/idp-metadata.xml");

                ParserPool parser = parserPool();
                try {
                    Document mdDocument = parser.parse(storeFile.getInputStream());
                    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(mdDocument.getDocumentElement());
                    return unmarshaller.unmarshall(mdDocument.getDocumentElement());
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new MetadataProviderException();
                }


            }
        };
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(provider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(false);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        return extendedMetadataDelegate;
    }
    
    // XML parser pool needed for OpenSAML parsing
    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setSignMetadata(false);
        return extendedMetadata;
    }

    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
        providers.add(ssoCircleExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }


}
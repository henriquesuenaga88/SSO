package sso.configs;

import static sso.db.DataSourceFactory.getOracleDataSource;
import static sso.saml.ProviderFactory.getSAMLAuthenticationProvider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
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
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.w3c.dom.Document;

import sso.db.AuthoritiesPopulator;
import sso.db.DataBaseUserService;
import sso.saml.FilterChainFactory;
import sso.saml.SAMLUserServiceImpl;

@Configuration
@ComponentScan(basePackages={"sso"})
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = false, securedEnabled = false, proxyTargetClass = false)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${openldap.name}")
    private String ldapName;
    
    @Value("${openldap.server-url}")
    private String ldapServerUrl;
    
    @Value("${openldap.search-base}")
    private String ldapSearchBase;
    
    @Value("${openldap.idp-type}")
    private String ldapIdpType;

    @Value("${openldap.username-attribute}")
    private String ldapUsernameAttribute;

    @Value("${openldap.domain}")
    private String ldapDomain;

    @Value("${openldap.group-search-base}")
    private String ldapGroupSearchBase;
//
//    @Value("${openldap.group-identify-user-by-dn}")
//    private String ldapGroupIdentifyUserByDN;
//
//    @Value("${openldap.groupMemberAttribute}")
//    private String ldapGroupMemberAttribute;
//
//    @Value("${openldap.groupType}")
//    private String ldapGroupType;
//
//    @Value("${openldap.name-attribute}")
//    private String ldapNameAttribute;

    @Autowired
    DataBaseUserService dataBaseUserService;
    
    @Autowired
    private SAMLUserServiceImpl samlUserServiceImpl;

    /*
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//        	.inMemoryAuthentication()
//        	.withUser("user").password("user").roles("USER")
//        	.and()
//        	.withUser("admin").password("admin").roles("ADMIN");
    	
    	auth
    		.jdbcAuthentication()
    		.dataSource(getOracleDataSource())
//    		.withDefaultSchema()
//    		.withUser("admin").password("etrust").roles("ADMIN")
//    		.and()
//    		.withUser("user").password("snow").roles("USER");
    		
            .usersByUsernameQuery(
                    "SELECT ID, LOGIN, PASSWORD, ENABLED FROM USERS WHERE LOGIN = ?")
            .authoritiesByUsernameQuery(
                    "SELECT UR.ID, UR.USER_ID, UR.AUTHORITY FROM USER_ROLES UR JOIN USERS U ON U.ID = UR.USER_ID WHERE U.LOGIN = ?");
    }*/
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        	.csrf()
        	.disable();
        
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
    public void configureAuthSource(AuthenticationManagerBuilder auth) throws Exception {
		LdapContextSource contextSource = new LdapContextSource();
		contextSource.setUrl(ldapServerUrl);
		contextSource.setBase(ldapGroupSearchBase);
		contextSource.setReferral("follow"); 
		contextSource.setUserDn(ldapSearchBase);
		contextSource.setPassword("123");
		contextSource.afterPropertiesSet();

		auth.ldapAuthentication()
			.contextSource(contextSource)
			.userSearchBase(ldapSearchBase)
			.userSearchFilter(ldapDomain)
			.ldapAuthoritiesPopulator(new AuthoritiesPopulator());

        auth
            .userDetailsService(dataBaseUserService)
            .passwordEncoder(new BCryptPasswordEncoder());

        auth.ldapAuthentication()
            .userDnPatterns(ldapUsernameAttribute) //openldap.username-attribute = uid
            .groupSearchBase(ldapGroupSearchBase) //openldap.group-search-base = ou=Groups,dc=codeitsolutions,dc=com,dc=br
            .contextSource(contextSource);
        
    	auth
    		.jdbcAuthentication()
    		.dataSource(getOracleDataSource())
    		.withUser("admin")
    			.password("admin")
    			.roles("ADMIN")
    		.and()
    		.withUser("user")
    			.password("user")
    			.roles("USER");
        auth.authenticationProvider(getSAMLAuthenticationProvider(samlUserServiceImpl));
    }

    /*
    @Autowired
    public void configureAuthSource(AuthenticationManagerBuilder auth) throws Exception {
    	
    	LdapContextSource contextSource = new LdapContextSource();
    	contextSource.setUrl(ldapServerUrl);
    	contextSource.setUserDn(ldapSearchBase);
    	contextSource.afterPropertiesSet();
    	
        auth
            .userDetailsService(dataBaseUserService)
            .passwordEncoder(new BCryptPasswordEncoder());

        auth.ldapAuthentication()
            .userDnPatterns(ldapUsernameAttribute) //openldap.username-attribute = uid
            .groupSearchBase(ldapGroupSearchBase) //openldap.group-search-base = ou=Groups,dc=codeitsolutions,dc=com,dc=br
            .contextSource(contextSource);
//            .url(ldapServerUrl) //openldap.server-url = ldap://ldap.codeitsolutions.com.br:389
//            .managerDn(ldapSearchBase) //openldap.search-base = ou=Users,dc=codeitsolutions,dc=com,dc=br
//            .managerPassword("123");
        
    	auth
    		.jdbcAuthentication()
    		.dataSource(getOracleDataSource())
    		.withUser("admin").password("admin").roles("ADMIN")
    		.and()
    		.withUser("user").password("user").roles("USER")
//    		.and()
//            .usersByUsernameQuery(
//                    "SELECT ID, USERNAME, PASSWORD, ENABLED FROM USERS WHERE USERNAME = ?")
//            .authoritiesByUsernameQuery(
//                    "SELECT UR.ID, UR.USER_ID, UR.AUTHORITY FROM USER_ROLES UR JOIN USERS U ON U.ID = UR.USER_ID WHERE U.USERNAME = ?");
    	;
        auth.authenticationProvider(getSAMLAuthenticationProvider(samlUserServiceImpl));
    }
*/
    
    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }
    
    // XML parser pool needed for OpenSAML parsing
    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }
    
    // Bindings, encoders and decoders used for creating and parsing messages
    @Bean
    public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }

    @Bean
    public HttpClient httpClient() {
        return new HttpClient(multiThreadedHttpConnectionManager());
    }

    // SAML Authentication Provider responsible for validating of received SAML
    // messages
    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails(samlUserServiceImpl);
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }
    
    // Provider of default SAML Context
    @Bean
    public SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl();
    }

    // Initialization of OpenSAML library
    @Bean
    public static SAMLBootstrap SAMLBootstrap() {
        return new SAMLBootstrap();
    }

    // Logger for SAML messages and events
    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    // SAML 2.0 WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }

    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // SAML 2.0 Web SSO profile
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    // SAML 2.0 Holder-of-Key Web SSO profile
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // SAML 2.0 ECP profile
    @Bean
    public WebSSOProfileECPImpl ecpprofile() {
        return new WebSSOProfileECPImpl();
    }

    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }

    // Central storage of cryptographic keys
    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader
                .getResource("classpath:/saml/samlKeystore.jks");
        String storePass = "nalle123";
        Map<String, String> passwords = new HashMap<String, String>();
        passwords.put("apollo", "nalle123");
        String defaultKey = "apollo";
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }

    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setSignMetadata(false);
        return extendedMetadata;
    }

    @Bean
    public SAMLDiscovery samlIDPDiscovery() {
        SAMLDiscovery idpDiscovery = new SAMLDiscovery();
        idpDiscovery.setIdpSelectionPath("/saml/idpSelection");
        return idpDiscovery;
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
        provider.setParserPool(ParserPoolHolder.getPool());
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(provider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(true);
        extendedMetadataDelegate.setMetadataRequireSignature(true);
        return extendedMetadataDelegate;
    }

    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
        providers.add(ssoCircleExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }

    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId("sso:sp");
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        return metadataGenerator;
    }

    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/landing");
        return successRedirectHandler;
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler =
                new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/login");
        return failureHandler;
    }

    @Bean
    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOHoKProcessingFilter;
    }

    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOProcessingFilter;
    }

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }

    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl("/");
        return successLogoutHandler;
    }

    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(),
                logoutHandler());
    }

    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[]{logoutHandler()},
                new LogoutHandler[]{logoutHandler()});
    }

    private ArtifactResolutionProfile artifactResolutionProfile() {
        final ArtifactResolutionProfileImpl artifactResolutionProfile =
                new ArtifactResolutionProfileImpl(httpClient());
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
        return artifactResolutionProfile;
    }

    @Bean
    public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
    }

    @Bean
    public HTTPSOAP11Binding soapBinding() {
        return new HTTPSOAP11Binding(parserPool());
    }

    @Bean
    public HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), velocityEngine());
    }

    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool());
    }

    @Bean
    public HTTPSOAP11Binding httpSOAP11Binding() {
        return new HTTPSOAP11Binding(parserPool());
    }

    @Bean
    public HTTPPAOS11Binding httpPAOS11Binding() {
        return new HTTPPAOS11Binding(parserPool());
    }
    
    @Bean
    public SAMLProcessorImpl processor() {
        Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
        bindings.add(httpRedirectDeflateBinding());
        bindings.add(httpPostBinding());
        bindings.add(artifactBinding(parserPool(), velocityEngine()));
        bindings.add(httpSOAP11Binding());
        bindings.add(httpPAOS11Binding());
        return new SAMLProcessorImpl(bindings);
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

}
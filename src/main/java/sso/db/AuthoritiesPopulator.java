package sso.db;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.stereotype.Service;

import sso.model.User;
import sso.repository.UserRepository;

@Service("authoritiesPopulator")
public class AuthoritiesPopulator implements LdapAuthoritiesPopulator {
	
	static final Logger LOG = LoggerFactory.getLogger(AuthoritiesPopulator.class);

	@Override
	public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
        try{
    		final User user = UserRepository.findBy(username);
            if (user==null){
                LOG.error("Threw exception in MyAuthoritiesPopulator::getGrantedAuthorities : User doesn't exist into DART database" );
            }
            else{
                //Use this if a user can have different roles
//              for(Role role : user.getRole()) {
//                  authorities.add(new SimpleGrantedAuthority(role.getRole()));
//              }
            	
                authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                return authorities;
            }
        } catch(Exception e){
        	LOG.error("Threw exception in MyAuthoritiesPopulator::getGrantedAuthorities : " + e.getStackTrace()); 
        }
        return authorities;
	}

}

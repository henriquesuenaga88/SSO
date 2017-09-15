package sso.db;

import java.util.Arrays;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import sso.model.User;
import sso.repository.UserRepository;

@Component("dataBaseUserService")
@Service
public class DataBaseUserService implements UserDetailsService {

	@Override
    public UserDetails loadUserByUsername(String login) {
		final User user = UserRepository.findBy(login);
//        User user = userRepository.findOneByLogin(login).orElseThrow(() -> new UsernameNotFoundException("User not found: " + login));
//        return new org.springframework.security.core.userdetails.User(login, user.getPassword(), Arrays.asList());
//    	return new org.springframework.security.core.userdetails.User(login, user.getPassword(), Arrays.asList());
    	return new org.springframework.security.core.userdetails.User(login, user.getPassword(), true, true, true, true, Arrays.asList());
    }
}

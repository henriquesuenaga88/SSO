package db;

import java.util.Arrays;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Component("dataBaseUserService")
@Service
public class DataBaseUserService implements UserDetailsService {

    public UserDetails loadUserByUsername(String login) {
//        User user = userRepository.findOneByLogin(login).orElseThrow(() -> new UsernameNotFoundException("User not found: " + login));
//        return new org.springframework.security.core.userdetails.User(login, user.getPassword(), Arrays.asList());
    	return new org.springframework.security.core.userdetails.User("user", "user", Arrays.asList());
    }
}

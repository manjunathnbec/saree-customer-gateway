package com.mnb.shree.silks.gateway.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(username.equalsIgnoreCase("manju")){
            return new User("manju", "$2a$12$NKFUJbFusq7DO6fQL9GCN..LgBDcZjonENL9I1UMO/GrENc7r2YZm",
                    new ArrayList<>());
        }
        throw new UsernameNotFoundException("User not found with username: " + username);
    }
}

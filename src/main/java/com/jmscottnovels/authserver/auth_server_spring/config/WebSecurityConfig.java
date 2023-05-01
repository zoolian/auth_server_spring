package com.jmscottnovels.authserver.auth_server_spring.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

// extends WebSecurityConfigurerAdpater is deprecated
@Configuration
public class WebSecurityConfig {

    // replaces WebSecurityConfigurerAdpater inheritance
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // provide a page to redirect the user to login
        return http.formLogin()
                .and().authorizeHttpRequests().anyRequest().authenticated()
                .and().build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // get from database
        UserDetails user1 = User.withUsername("joe").password("12345").authorities("read").build();

        //use JdbcUserDetailsManager(Datasource datasource)
        // https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/provisioning/JdbcUserDetailsManager.html
        InMemoryUserDetailsManager uds = new InMemoryUserDetailsManager();

        uds.createUser(user1);
        return uds;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // use bCrypt password
        return NoOpPasswordEncoder.getInstance();
    }
}

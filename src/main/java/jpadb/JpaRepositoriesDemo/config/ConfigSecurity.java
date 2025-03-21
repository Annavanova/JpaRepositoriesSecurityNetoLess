package jpadb.JpaRepositoriesDemo.config;

import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableGlobalMethodSecurity
public class ConfigSecurity extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("Admin").password("{bcrypt}admin").authorities("READ","WRITE","DELETE")
                .and()
                .withUser("user1").password("{noop}password1").roles("READ")
                .and()
                .withUser("user2").password("{noop}password2").roles("WRITE")
                .and()
                .withUser("user3").password("{noop}password3").roles("DELETE", "WRITE");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .and()
                .authorizeRequests().antMatchers("/persons/city").permitAll()
                .and()
                .authorizeRequests().antMatchers("/persons/age").hasAuthority("age")
                .and()
                .authorizeRequests().antMatchers("/persons/name-surname").hasAuthority("name-surname")
                .and()
                .authorizeRequests().anyRequest().authenticated();
    }
}


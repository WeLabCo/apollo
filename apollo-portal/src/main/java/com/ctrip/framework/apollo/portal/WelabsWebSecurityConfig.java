package com.ctrip.framework.apollo.portal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.util.List;
import java.util.Map;

/**
 * Created by magicdog on 2017/1/13.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(WelabsWebSecurityConfig.AuthUserInfoProperties.class)
@Order(value = Integer.MIN_VALUE + 20)
public class WelabsWebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private WelabsWebSecurityConfig.AuthUserInfoProperties authUserInfoProperties;

    private static final String USER_NAME = "username";
    private static final String PASS_WORD = "password";
    private static final String ROLES = "ADMIN";

    public WelabsWebSecurityConfig(){

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/lib/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .antMatcher("/**")
                .authorizeRequests()
                .anyRequest().hasAnyRole("ADMIN", "API")
                .and()
                .httpBasic();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        InMemoryUserDetailsManagerConfigurer memoryUserDetailsManagerConfigurer = auth.inMemoryAuthentication();
        List<Map<String,String>> userAuthList = authUserInfoProperties.getUserinfo();
        for (int i = 0; i < userAuthList.size() ; i ++){
            Map<String,String> authInfo = userAuthList.get(i);
            String username = authInfo.get(USER_NAME);
            String password = authInfo.get(PASS_WORD);
            memoryUserDetailsManagerConfigurer.withUser(username).password(password).roles(ROLES);
        }
    }

    @ConfigurationProperties(prefix = "auth.welabs")
    public static class AuthUserInfoProperties {
        private List<Map<String, String>> userinfo;

        public List<Map<String, String>> getUserinfo() {
            return userinfo;
        }

        public void setUserinfo(List<Map<String, String>> userinfo) {
            this.userinfo = userinfo;
        }
    }

}

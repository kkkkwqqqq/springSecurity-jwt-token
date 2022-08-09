package com.example.demo.config;

import com.example.demo.JwtAuthenticationFilter;
import com.example.demo.JwtAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.PrintWriter;


/**
 * Spring Security Config
 *
 * @author kwq
 * @date Nov 20, 2018
 */
@Configuration
@EnableWebSecurity//使secuity生效
@EnableGlobalMethodSecurity(prePostEnabled = true)//开启secuity的注解
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 使用自定义身份验证组件
        auth.authenticationProvider(new JwtAuthenticationProvider(userDetailsService));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 禁用X-Content-Type-Options
        http.headers().contentTypeOptions().disable();
        // 禁用 csrf, 由于使用的是JWT，我们这里不需要csrf
        http.headers().frameOptions().disable().and().cors().and().csrf().disable()
                .authorizeRequests()
                //放行登录接口
                .antMatchers("/login").permitAll()
                // 跨域预检请求
                //.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // 免登录
                //.antMatchers("/**").permitAll()
                // swagger
                .antMatchers("/swagger-ui.html").permitAll()
                .antMatchers("/swagger-resources").permitAll()
                .antMatchers("/webjars/springfox-swagger-ui/**").permitAll()

                // 其他所有请求需要身份认证
                .anyRequest().authenticated();

        http.addFilterBefore(new JwtAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

}

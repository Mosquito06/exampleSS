package com.example.ss;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS, USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN, SYS, USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http.authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                // 구체적인 범위가 먼저 작성 되어야 함!
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http.formLogin();
    }

    //    @Override
//    protected void configure(HttpSecurity http) throws Exception
//    {
//        // 리액트 연동 참고 : https://www.baeldung.com/spring-security-login-react
//        http.authorizeHttpRequests()
//            .anyRequest()
//            .authenticated();
//
//        http.formLogin()
//            //.loginPage("/loginPage")
//            .defaultSuccessUrl("/")
//            .failureUrl("/")
//            .usernameParameter("userId")
//            .passwordParameter("passwd")
//            .loginProcessingUrl("/login_proc")
//            .successHandler(new AuthenticationSuccessHandler()
//            {
//                @Override
//                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                    System.out.println("authentication" + authentication.getName());
//                    response.sendRedirect("/");
//                }
//            })
//            .failureHandler(new AuthenticationFailureHandler() {
//                @Override
//                public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                    System.out.println("exception" + exception.getMessage());
//                    response.sendRedirect("/");
//                }
//            })
//            .permitAll();
//
//        http.logout()
//            .logoutUrl("/logout")
//            .logoutSuccessUrl("/login")
//            .addLogoutHandler(new LogoutHandler() {
//                @Override
//                public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                    HttpSession session = request.getSession();
//                    session.invalidate();
//                }
//            })
//            .logoutSuccessHandler(new LogoutSuccessHandler() {
//                @Override
//                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                    response.sendRedirect("/login");
//                }
//            })
//            .deleteCookies("remember-me");
//
//        http.sessionManagement()
//            .maximumSessions(1)
//            .maxSessionsPreventsLogin(false);
//
//
//    }
}

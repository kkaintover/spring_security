package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	   @Override
	   protected void configure(HttpSecurity http) throws Exception {
		   http.authorizeRequests()
	        .antMatchers("/loginForm").permitAll()
	        .anyRequest().authenticated();

		   http.formLogin()
	        .loginProcessingUrl("/login") // ログイン処理のパス
	        .loginPage("/loginForm") // ログインページの指定
	        .usernameParameter("email") // ログインページのメールアドレス
	        .passwordParameter("password") // ログインページのパスワード
	        .defaultSuccessUrl("/home", true) // ログイン成功後のパス
	        .failureUrl("/loginForm?error"); //

		   http.logout()
	        .logoutUrl("/logout") //ログアウト処理のパス
	        .logoutSuccessUrl("/loginForm");

		   http.authorizeRequests()
           .antMatchers("/loginForm").permitAll()
           .antMatchers("/admin").hasAuthority("ADMIN") // 管理者のみ/adminにアクセスできる
           .anyRequest().authenticated();
	    }

	   @Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }

}

package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final CorsConfig corsConfig;

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}


	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
		http.addFilterBefore (new MyFilter3 (), SecurityContextPersistenceFilter.class);
		http.csrf(csrf -> csrf.disable());
		http.cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()));
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.formLogin(form -> form.disable());
		http.httpBasic(basic -> basic.disable());
		http.addFilter (new JwtAuthenticationFilter (authenticationManager));
		
		http.authorizeHttpRequests(auth -> auth
			.requestMatchers("/api/v1/user/**")
				.hasAnyRole("USER", "MANAGER", "ADMIN")
			.requestMatchers("/api/v1/manager/**")
				.hasAnyRole("MANAGER", "ADMIN")
			.requestMatchers("/api/v1/admin/**")
				.hasRole("ADMIN")
			.anyRequest().permitAll()
		);
		
		return http.build();
	}
}

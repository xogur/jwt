package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable());
		http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.formLogin(form -> form.disable());
		http.httpBasic(basic -> basic.disable());
		
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
	
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		
		// 자격 증명 허용
		configuration.setAllowCredentials(true);
		
		// 모든 도메인 허용 (프로덕션에서는 특정 도메인만 허용하도록 수정)
		configuration.addAllowedOriginPattern("*");
		
		// 모든 헤더 허용
		configuration.addAllowedHeader("*");
		
		// 모든 HTTP 메서드 허용
		configuration.addAllowedMethod("*");
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		
		return source;
	}
}

package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		
		// 자격 증명 허용
		config.setAllowCredentials(true);
		
		// 모든 도메인 허용 (프로덕션에서는 특정 도메인만 허용하도록 수정)
		config.addAllowedOriginPattern("*");
		
		// 모든 헤더 허용
		config.addAllowedHeader("*");
		
		// 모든 HTTP 메서드 허용
		config.addAllowedMethod("*");
		
		// 모든 경로에 CORS 설정 적용
		source.registerCorsConfiguration("/**", config);
		
		return source;
	}
	
	@Bean
	public CorsFilter corsFilter() {
		return new CorsFilter(corsConfigurationSource());
	}
}


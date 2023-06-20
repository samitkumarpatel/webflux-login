package com.example.webfluxlogin;

import lombok.SneakyThrows;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.Id;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

@SpringBootApplication
public class WebfluxLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(WebfluxLoginApplication.class, args);
	}

	@Bean
	public RouterFunction routerFunction() {
		return RouterFunctions
				.route()
				.path("/message", builder -> builder
						.GET("", request -> ServerResponse.ok().build()))
				.path("/user", builder -> builder
						.GET("", request -> ServerResponse.noContent().build())
						.GET("/{id}", request -> ServerResponse.noContent().build())
						.POST("", request -> ServerResponse.noContent().build())
						.PUT("/{id}", request -> ServerResponse.noContent().build())
						.DELETE("/{id}", request -> ServerResponse.noContent().build()))
				.build();
	}

}

@Component
@EnableWebFluxSecurity
class CustomWebSecurity {
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@SneakyThrows
	public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
		return http
				.authorizeExchange(exchanges -> exchanges.pathMatchers(HttpMethod.POST, "/user").permitAll().anyExchange().authenticated())
				.csrf(csrf -> csrf.disable())
				.build();
	}
}
record Users(@Id Long id, String username, String password){}

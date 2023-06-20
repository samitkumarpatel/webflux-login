package com.example.webfluxlogin;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.Id;

import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import java.util.Collection;
import java.util.Optional;

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
record Users(@Id Long id, String username, String password) implements UserDetails {
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}

interface UsersRepository extends R2dbcRepository<Users, Long>{
	public Optional<Users> findByUsername(String username);
}
@Service
@RequiredArgsConstructor
@Slf4j
class UsersService implements UserDetailsService {
	private final UsersRepository usersRepository;

	@Override
	public UserDetails loadUserByUsername(String username) {
		log.info("loadUserByUsername: {}", username);
		return usersRepository
				.findByUsername(username)
				.orElseThrow(() -> new UsersNotFoundException("User not found"));

	}
}

@ResponseStatus(HttpStatus.NOT_EXTENDED)
class UsersNotFoundException extends RuntimeException {
	public UsersNotFoundException(String message) {
		super(message);
	}
}
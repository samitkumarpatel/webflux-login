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
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
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
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Optional;

@SpringBootApplication
public class WebfluxLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(WebfluxLoginApplication.class, args);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public RouterFunction<ServerResponse> routerFunction(UsersRepository usersRepository, PasswordEncoder passwordEncoder) {
		return RouterFunctions
				.route()
				.path("/message", builder -> builder
						.GET("", request -> ServerResponse.ok().body(Mono.just("Hello World!"), String.class)))
				.path("/user", builder -> builder
						.GET("", request -> ServerResponse.ok().body(usersRepository.findAll(), Users.class))
						.GET("/{id}", request -> ServerResponse.ok().body(usersRepository.findById(Long.parseLong(request.pathVariable("id"))), Users.class))
						.POST("", request -> {
							return request.bodyToMono(Users.class)
									.map(users -> new Users(users.id(), users.getUsername(), passwordEncoder.encode(users.getPassword())))
									.flatMap(usersRepository::save)
									.flatMap(users -> ServerResponse.ok().build());
						})
						.PUT("/{id}", request -> ServerResponse.noContent().build())
						.DELETE("/{id}", request -> ServerResponse.noContent().build()))
				.build();
	}

}

@Component
@EnableWebFluxSecurity
@RequiredArgsConstructor
@Slf4j
class CustomWebSecurity {

	private final ReactiveUserDetailsService reactiveUserDetailsService;
	private final PasswordEncoder passwordEncoder;
	@Bean
	@SneakyThrows
	public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http, ReactiveAuthenticationManager authenticationManager) {
		return http
				.authorizeExchange(exchanges -> exchanges
						.pathMatchers( "/user").permitAll()
						.anyExchange().authenticated()
				)
				.csrf(ServerHttpSecurity.CsrfSpec::disable)
//				.authenticationManager(authentication -> {
//					return ReactiveSecurityContextHolder.getContext()
//							.map(securityContext -> securityContext.getAuthentication())
//							.filter(auth -> auth.isAuthenticated())
//							.switchIfEmpty(Mono.defer(() -> authenticationManager.authenticate(authentication)))
//							.flatMap(auth -> Mono.just(new UsernamePasswordAuthenticationToken(auth.getPrincipal(), auth.getCredentials(), auth.getAuthorities())));
//				})
				.authenticationManager(authenticationManager)
				.formLogin(Customizer.withDefaults()) // will display login page
				.httpBasic(Customizer.withDefaults()) // will allow for basic auth
				.build();
	}

//	// Inmemory user
//	@Bean
//	public MapReactiveUserDetailsService mapReactiveUserDetailsService(PasswordEncoder passwordEncoder) {
//		return new MapReactiveUserDetailsService(
//				org.springframework.security.core.userdetails.User.withUsername("user")
//						.password(passwordEncoder.encode("password"))
//						.roles("USER")
//						.build()
//		);
//	}


	/*
	// This approach is not the most efficiant way
	@Bean
	public ReactiveAuthenticationManager reactiveAuthenticationManager() {
		return authentication -> {
			var usernameInput = authentication.getName();
			var passwordInput = authentication.getCredentials().toString();
			log.info("{} is trying to login", usernameInput);
			return reactiveUserDetailsService.findByUsername(usernameInput)
					.doOnSuccess(userDetails -> log.info("success {}", userDetails))
					.doOnError(throwable -> log.error("error {}", throwable.getMessage()))
					.filter(userDetails -> passwordEncoder.matches(passwordInput, userDetails.getPassword()))
					.map(userDetails -> new UsernamePasswordAuthenticationToken(userDetails, passwordInput, userDetails.getAuthorities()));
		};
	}*/

	@Bean
	public ReactiveAuthenticationManager authenticationManager(ReactiveUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
		UserDetailsRepositoryReactiveAuthenticationManager authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
		authenticationManager.setPasswordEncoder(passwordEncoder);
		return authenticationManager;
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
	public Mono<Users> findByUsername(String username);
}

@ResponseStatus(HttpStatus.NOT_EXTENDED)
class UsersNotFoundException extends RuntimeException {
	public UsersNotFoundException(String message) {
		super(message);
	}
}

@Service
@RequiredArgsConstructor
class UsersDetailsService implements ReactiveUserDetailsService {
	private final UsersRepository usersRepository;
	@Override
	public Mono<UserDetails> findByUsername(String username) {
		return usersRepository.findByUsername(username)
				.switchIfEmpty(Mono.error(new BadCredentialsException("User not found")))
				.onErrorResume(throwable -> Mono.error(new BadCredentialsException("User not found")))
				.map(user -> user)
				.cast(UserDetails.class);
	}
}
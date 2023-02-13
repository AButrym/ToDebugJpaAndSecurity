package com.example.demo;

import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.hibernate.annotations.NaturalId;
import org.mapstruct.Mapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static org.mapstruct.ReportingPolicy.IGNORE;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@SpringBootApplication
public class Demo4Application {
    public static void main(String[] args) {
        SpringApplication.run(Demo4Application.class, args);
    }
}

@Mapper(componentModel = "spring", unmappedTargetPolicy = IGNORE)
interface Mappers {
    TheController.CreatedUser toCreatedUser(UserEntity userEntity);

    default UserDetails toUserDetails(UserEntity userEntity) {
        return User.withUsername(userEntity.getName())
                .password(userEntity.getPassword())
                .authorities(userEntity.getAuthorities().stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList()
                ).build();
    }
}

interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByNameIgnoreCase(String name);
    boolean existsByNameIgnoreCase(String name);
}

@Getter @Setter @NoArgsConstructor
@Builder @AllArgsConstructor
@Entity
class UserEntity {
    @Id @GeneratedValue
    Long id;
    @NaturalId @Column(unique = true, updatable = false)
    String name;
    String password;
    @ElementCollection(fetch = FetchType.EAGER)
    Collection<String> authorities;
}

@EnableWebSecurity @EnableMethodSecurity
@Configuration
class SecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(c -> c
                .requestMatchers("/h2").permitAll()
                .requestMatchers(POST, "/register").permitAll()
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated());
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.httpBasic();
//        http.csrf().disable();
        http.csrf().ignoringRequestMatchers("/register");
//        http.cors().disable();
//        http.headers().frameOptions().disable();
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(
            UserRepository repository,
            Mappers mapper
    ) {
        return name -> repository.findByNameIgnoreCase(name)
                .map(mapper::toUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException(name + " not found"));
    }
}

@AllArgsConstructor
@RestController
class TheController {
    UserService service;
    Mappers mapper;

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/hello")
    public String hello(Authentication authentication) {
        return "Hello, " + authentication.getName();
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    CreatedUser register(@Valid @RequestBody NewUser newUser) {
        return mapper.toCreatedUser(service.register(newUser.name(), newUser.password()));
    }

    record NewUser(
            @NotBlank String name,
            @NotBlank String password) {}

    record CreatedUser(Long id, String name) {}
}

@AllArgsConstructor
@Transactional
@Service
class UserService {
    UserRepository repository;
    PasswordEncoder passwordEncoder;

    public UserEntity register(String username, String password) {
        if (!repository.existsByNameIgnoreCase(username))
            return repository.save(UserEntity.builder()
                    .name(username)
                    .password(passwordEncoder.encode(password))
                    .authorities(List.of("ROLE_USER"))
                    .build()
            );
        else
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Username '" + username + "' is already occupied");
    }
}

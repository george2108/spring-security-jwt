package com.example.springsecurityjwt;

import com.example.springsecurityjwt.models.ERole;
import com.example.springsecurityjwt.models.RoleEntity;
import com.example.springsecurityjwt.models.UserEntity;
import com.example.springsecurityjwt.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	UserRepository userRepository;

	@Bean
	CommandLineRunner init() {
		return args -> {
			UserEntity userEntity = UserEntity.builder()
					.username("jorge")
					.password(passwordEncoder.encode("password"))
					.email("jorge@gmail.com")
					.roles(Set.of(RoleEntity.builder()
							.name(ERole.ADMIN)
							.build()))
					.build();
			UserEntity user2 = UserEntity.builder()
					.username("jorge2")
					.password(passwordEncoder.encode("password"))
					.email("jorge2@gmail.com")
					.roles(Set.of(RoleEntity.builder()
							.name(ERole.USER)
							.build()))
					.build();
			UserEntity user3 = UserEntity.builder()
					.username("jorge3")
					.password(passwordEncoder.encode("password"))
					.email("jorge3@gmail.com")
					.roles(Set.of(RoleEntity.builder()
							.name(ERole.GUEST)
							.build()))
					.build();

			userRepository.save(userEntity);
			userRepository.save(user2);
			userRepository.save(user3);
		};
	}

}

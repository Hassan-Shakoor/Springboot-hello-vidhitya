package com.example.demo;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
		return args -> {
			System.out.println("Mapping all request mappings:");
			RequestMappingHandlerMapping requestMappingHandlerMapping = ctx.getBean(RequestMappingHandlerMapping.class);
			requestMappingHandlerMapping.getHandlerMethods().forEach((key, value) -> System.out.println(key + " : " + value));
		};
	}
}

package com.xideral.gateway.gateway_server.configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

//@Component
public class AuthGlobalFilter { //implements GlobalFilter {
//
//    @Autowired
//    private WebClient.Builder webClientBuilder;
//
//    private static final List<String> EXCLUDED_PATHS = List.of("/api/auth/login", "/api/auth/validate");
//
//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
//        String path = exchange.getRequest().getPath().value();
//
//        //Rutas Excluidas
//        if (EXCLUDED_PATHS.stream().anyMatch(path::startsWith)) {
//            return chain.filter(exchange);
//        }
//
//        // Validar si el encabezado está presente
//        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//            return exchange.getResponse().setComplete();
//        }
//
//        String token = authHeader.replace("Bearer ", ""); // Quitar "Bearer "
//
//        return validateToken(token).flatMap(isValid -> {
//            if (Boolean.TRUE.equals(isValid)) {
//                return chain.filter(exchange);
//            } else {
//                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//                return exchange.getResponse().setComplete();
//            }
//        }).onErrorResume(e -> {
//            e.printStackTrace();
//            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
//            return exchange.getResponse().setComplete();
//        });
//
//    }
//
//    public Mono<Boolean> validateToken(String token) {
//        return webClientBuilder
//                .baseUrl("lb://AUTH-SERVICE")
//                .build().get()
//                .uri("/auth/validate?token={token}",token)
//                .retrieve()
//                .bodyToMono(Boolean.class);
//    }
}
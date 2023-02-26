package com.zu.jwtokenutil;

import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.Map;

public interface JwTokenUtil {
    Mono<Void> setAudience(String audience);
    Mono<Void> setId(String id);
    Mono<Void> setIssuer(String issuer);
    Mono<Void> setSubject(String subject);
    Mono<Void> setClaims(Map<String, Object> claims);
    Mono<String> getSubjectFromToken(String token);
    Mono<Object> getClaimFromToken(String token, String claimKey);
    Mono<String> getAudienceFromToken(String token);
    Mono<String> getIdFromToken(String token);
    Mono<Date> getIssueDateFromToken(String token);
    Mono<String> getIssuerFromToken(String token);
    Mono<Date> getExpirationDateFromToken(String token);
    Mono<Boolean> isTokenExpired(String token);
    Mono<String> getToken();
    Mono<Void> addClaim(String key, Object value);
}

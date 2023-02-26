package com.zu.jwtokenutil.impl;

import com.zu.jwtokenutil.JwTokenUtil;
import com.zu.jwtokenutil.constant.JwtAlgorithmConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import reactor.core.publisher.Mono;
import reactor.core.publisher.SignalType;
import reactor.core.scheduler.Schedulers;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

public class JwTokenUtilImpl implements JwTokenUtil {

    private String subject;
    private String audience;
    private String id;
    private String issuer;
    private Map<String, Object> claims;

    private final SignatureAlgorithm jwtSignatureAlgorithm;
    private final String secretKey;
    private final Long expirationTimeMillis;
    private final String CLAIM_NOT_FOUND = "Claim not found, make sure you added it into claims";

    private final Predicate<Throwable> CLAIM_NOT_FOUND_PREDICATE = throwable -> throwable instanceof NullPointerException;

    private final Consumer<SignalType> RESET_VALUES_CONSUMER = signalType -> {
        if(SignalType.ON_COMPLETE.equals(signalType)) {
            this.subject = null;
            this.audience = null;
            this.id = null;
            this.issuer = null;
            this.claims = null;
        }
    };

    public JwTokenUtilImpl(String jwtSignatureAlgorithmType, String secretKey, Long expirationTimeMillis) {
        this.jwtSignatureAlgorithm = getJwtSignatureAlgorithm(jwtSignatureAlgorithmType);
        this.secretKey = secretKey;
        this.expirationTimeMillis = expirationTimeMillis;
        this.subject = null;
        this.audience = null;
        this.id = null;
        this.issuer = null;
        this.claims = null;
    }

    private SignatureAlgorithm getJwtSignatureAlgorithm(String jwtSignatureAlgorithmType) {
        switch (jwtSignatureAlgorithmType) {
            case JwtAlgorithmConstant.HS512:
                return SignatureAlgorithm.HS512;
            case JwtAlgorithmConstant.HS384:
                return SignatureAlgorithm.HS384;
            default:
                return SignatureAlgorithm.HS256;
        }
    }

    @Override
    public Mono<Void> setSubject(String subject) {
        return Mono.fromRunnable(() -> this.subject = subject);
    }

    @Override
    public Mono<Void> setClaims(Map<String, Object> claims) {
        return Mono.fromRunnable(() -> this.claims = claims);
    }

    @Override
    public Mono<Void> setAudience(String audience) {
        return Mono.fromRunnable(() -> this.audience = audience);
    }

    @Override
    public Mono<Void> setId(String id) {
        return Mono.fromRunnable(() -> this.id = id);
    }

    @Override
    public Mono<Void> setIssuer(String issuer) {
        return Mono.fromRunnable(() -> this.issuer = issuer);
    }

    @Override
    public Mono<Void> addClaim(String key, Object value) {
        if(Objects.isNull(claims)) {
            claims = new HashMap<>();
        }
        return Mono.fromRunnable(() -> claims.put(key, value));
    }

    @Override
    public Mono<String> getSubjectFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<String> getAudienceFromToken(String token) {
        return getClaimFromToken(token, Claims::getAudience)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<String> getIdFromToken(String token) {
        return getClaimFromToken(token, Claims::getId)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Date> getIssueDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<String> getIssuerFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuer)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Object> getClaimFromToken(String token, String claimKey) {
        Mono<Claims> claims = getAllClaimsFromToken(token);

        return claims.map(claim  -> claim.get(claimKey))
                .onErrorReturn(CLAIM_NOT_FOUND_PREDICATE, CLAIM_NOT_FOUND)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Date> getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Boolean> isTokenExpired(String token) {
        Mono<Date> expirationDate = getClaimFromToken(token, Claims::getExpiration);
        return expirationDate.map(date -> date.before(new Date()))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<String> getToken() {
        return Mono.fromSupplier(() ->
                Jwts.builder()
                        .setSubject(this.subject)
                        .addClaims(this.claims)
                        .setIssuedAt(new Date(System.currentTimeMillis()))
                        .setAudience(this.audience)
                        .setId(this.id)
                        .setIssuer(this.issuer)
                        .setExpiration(new Date(System.currentTimeMillis() + this.expirationTimeMillis))
                        .signWith(this.jwtSignatureAlgorithm,secretKey)
                        .compact())
                .doFinally(RESET_VALUES_CONSUMER)
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Claims> getAllClaimsFromToken(String token) {
        return Mono.fromSupplier(() -> Jwts.parser().setSigningKey(this.secretKey).parseClaimsJws(token).getBody());
    }

    private <T> Mono<T> getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        Mono<Claims> claims = getAllClaimsFromToken(token);
        return claims.map(claimsResolver::apply)
                .onErrorReturn(CLAIM_NOT_FOUND_PREDICATE, (T) CLAIM_NOT_FOUND)
                .subscribeOn(Schedulers.boundedElastic());
    }
}

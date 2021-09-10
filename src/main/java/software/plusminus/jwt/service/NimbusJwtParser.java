package software.plusminus.jwt.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.ObjectUtils;
import software.plusminus.authentication.AuthenticationParameters;

import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Slf4j
public class NimbusJwtParser implements JwtParser {

    private final JWKSource<? extends com.nimbusds.jose.proc.SecurityContext> jwkSource;
    private final IssuerService issuerService;

    public NimbusJwtParser(JWKSource<? extends com.nimbusds.jose.proc.SecurityContext> jwkSource,
                           IssuerService issuerService) {
        this.jwkSource = jwkSource;
        this.issuerService = issuerService;
    }

    @Override
    @SuppressWarnings("npathcomplexity")
    public AuthenticationParameters parseToken(String text) {
        if (text == null) {
            log.warn("no authorisation token.");
            return null;
        }

        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(text);
        } catch (ParseException e) {
            log.warn("incorrect access token format.");
            return null;
        }

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            log.warn("unable to parse claims.");
            return null;
        }

        boolean succeed = checkHeaderAndKeyId(jwt.getHeader())
                && checkExpirationTime(claims.getExpirationTime())
                && checkSignature(jwt)
                && checkIssuer(claims.getIssuer());
        if (!succeed) {
            return null;
        }

        Set<String> roles;
        try {
            List<String> rolesClaim = claims.getStringListClaim("roles");
            if (rolesClaim == null) {
                roles = Collections.emptySet();
            } else {
                roles = Collections.unmodifiableSet(new HashSet<>(rolesClaim)); 
            }
        } catch (ParseException e) {
            throw new SecurityException(e);
        }
        
        AuthenticationParameters parameters = AuthenticationParameters.builder()
                .username(claims.getSubject())
                .roles(roles)
                .otherParameters(claims.getClaims())
                .build();
        return parameters;
    }

    private boolean checkHeaderAndKeyId(JWSHeader header) {
        if (header == null /*|| header.getKeyID() == null*/) {
            log.warn("missing key id property in access token.");
            return false;
        }

        return true;
    }

    private boolean checkExpirationTime(Date expirationTime) {
        if (expirationTime == null || new Date().after(expirationTime)) {
            log.warn("access token has expired.");
            return false;
        }

        return true;
    }

    private boolean checkSignature(SignedJWT jwt) {
        JWKSelector selector = new JWKSelector(
                new JWKMatcher.Builder()
                        .keyID(jwt.getHeader().getKeyID())
                        .publicOnly(true)
                        .build());
        List<JWK> keys;
        try {
            keys = jwkSource.get(selector, null);
        } catch (KeySourceException e) {
            log.warn("key source error.", e);
            return false;
        }

        if (keys.isEmpty()) {
            log.warn("key not found.");
            return false;
        }

        try {
            if (!jwt.verify(new RSASSAVerifier((RSAKey) keys.get(0)))) {
                log.warn("verification failed.");
                return false;
            }
        } catch (JOSEException e) {
            log.warn("verification failed with an error.", e);
            return false;
        }

        return true;
    }
    
    private boolean checkIssuer(@Nullable String issuer) {
        return ObjectUtils.nullSafeEquals(issuer, issuerService.currentIssuer());
    }

}
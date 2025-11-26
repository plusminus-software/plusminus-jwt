package software.plusminus.jwt.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import software.plusminus.jwt.service.IssuerContext;
import software.plusminus.jwt.service.JwtParser;
import software.plusminus.jwt.service.NimbusJwtParser;

import java.security.interfaces.RSAPublicKey;

@Configuration
@ComponentScan("software.plusminus.jwt")
public class JwtAutoconfig {

    @Bean
    JwtParser jwtParser(RSAPublicKey publicKey,
                        IssuerContext issuerContext) {
        return new NimbusJwtParser(
                //new RemoteJWKSet<>(new URL(PUBLIC_KEY_URL)));
                createJwkSet(publicKey),
                issuerContext);
    }

    private ImmutableJWKSet createJwkSet(RSAPublicKey publicKey) {
        return new ImmutableJWKSet<>(new JWKSet(
                new RSAKey(publicKey, KeyUse.SIGNATURE,
                        null, null, "kid",
                        null, null, null, null, null)));
    }
}

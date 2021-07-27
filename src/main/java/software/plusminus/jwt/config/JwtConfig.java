package software.plusminus.jwt.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.plusminus.jwt.service.IssuerService;
import software.plusminus.jwt.service.JwtParser;
import software.plusminus.jwt.service.NimbusJwtParser;

import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtConfig {

    @Bean
    public JwtParser parser(RSAPublicKey publicKey,
                            IssuerService issuerService) {
        return new NimbusJwtParser(
                //new RemoteJWKSet<>(new URL(PUBLIC_KEY_URL)));
                createJwkSet(publicKey),
                issuerService);
    }

    private ImmutableJWKSet createJwkSet(RSAPublicKey publicKey) {
        return new ImmutableJWKSet<>(new JWKSet(
                new RSAKey(publicKey, KeyUse.SIGNATURE,
                        null, null, "kid",
                        null, null, null, null, null)));
    }
}

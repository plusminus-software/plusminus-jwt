package software.plusminus.jwt.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import software.plusminus.authentication.AuthenticationParameters;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(SpringRunner.class)
@SpringBootTest
@SuppressWarnings("classdataabstractioncoupling")
public class NimbusJwtParserTest {

    private final KeyPair keysHolder;
    private final RSAKey publicKey;
    private final JWSSigner signer;
    private final IssuerService issuerService;

    private NimbusJwtParser parser;
    private String accessToken;

    public NimbusJwtParserTest() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        keysHolder = generator.generateKeyPair();
        signer = new RSASSASigner(keysHolder.getPrivate());
        publicKey = rsakey(keysHolder.getPublic(), "keyId");
        issuerService = mock(IssuerService.class);
    }

    private static Date expirationTime(int offset) {
        return new Date(new Date().getTime() + offset * 1000);
    }

    private static RSAKey rsakey(PublicKey publicKey, String kid) {
        return new RSAKey(
                (RSAPublicKey) publicKey,
                KeyUse.SIGNATURE,
                null,
                null,
                kid,
                null,
                null,
                null,
                null,
                null);
    }

    private static JWTClaimsSet claims(String roles, String domain, Date expirationTime) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("test");
        builder.claim("email", "test");
        builder.issueTime(new Date());

        if (StringUtils.isNotEmpty(roles)) {
            builder.claim("roles", Collections.singletonList(roles));
        }

        if (StringUtils.isNotEmpty(domain)) {
            builder.claim("domain", domain);
        }

        if (expirationTime != null) {
            builder.expirationTime(expirationTime);
        }
        return builder.build();
    }

    @Before
    public void setUp() throws JOSEException {
        parser = new NimbusJwtParser(
                new ImmutableJWKSet<>(new JWKSet(publicKey)),
                issuerService);
        JWTClaimsSet claims = claims("test-role", "some_domain", expirationTime(60));
        accessToken = jws(claims, publicKey).serialize();
    }

    @Test
    public void testUnauthorized() {
        AuthenticationParameters parameters = parser.parseToken(null);
        assertThat(parameters).isNull();
    }

    @Test
    public void testIncorrectApiKey() {
        AuthenticationParameters parameters = parser.parseToken("foo");
        assertThat(parameters).isNull();
    }

    @Test
    public void testValidAccessToken() throws JOSEException {
        AuthenticationParameters parameters = parser.parseToken(accessToken);

        assertThat(parameters).isNotNull();
        assertThat(parameters.getUsername()).isEqualTo("test");
        assertThat(parameters.getRoles()).contains("test-role");
    }

    @Test
    public void testInvalidAccessToken() throws JOSEException {
        testInvalidAccessToken(accessToken.toUpperCase());
        testInvalidAccessToken(" ." + accessToken);
        testInvalidAccessToken("Vendor " + accessToken);
    }

    private void testInvalidAccessToken(String token) throws JOSEException {
        AuthenticationParameters parameters = parser.parseToken(token);
        assertThat(parameters).isNull();
    }

    @Test
    public void testAccessTokenWithUnknownKey() throws JOSEException {
        JWTClaimsSet claims = claims(
                "test", "some_domain", expirationTime(60));
        String authorization = jws(
                claims, rsakey(keysHolder.getPublic(), "foo")).serialize();

        AuthenticationParameters parameters = parser.parseToken(authorization);

        assertThat(parameters).isNull();
    }

    @Test
    public void testAccessTokenWithoutRoles() throws JOSEException {

        JWTClaimsSet claims = claims(null,
                "_some_domain",
                expirationTime(60));
        String token = jws(claims, publicKey).serialize();

        AuthenticationParameters parameters = parser.parseToken(token);

        assertThat(parameters).isNotNull();
        assertThat(parameters.getUsername()).isEqualTo("test");
        assertThat(parameters.getRoles()).isEmpty();
    }

    @Test
    public void testJwtWithExpiredTime() throws JOSEException {
        String authorization = jws(
                claims("point-observation",
                        "some_domain",
                        expirationTime(-60)),
                publicKey)
                .serialize();

        AuthenticationParameters parameters = parser.parseToken(authorization);

        assertThat(parameters).isNull();
    }

    private JWSObject jws(JWTClaimsSet claims, RSAKey rsaPublicKey)
            throws JOSEException {
        JWSObject jws = new JWSObject(
                new JWSHeader(
                        JWSAlgorithm.RS512,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        rsaPublicKey.getKeyID(),
                        null,
                        null),
                new Payload(claims.toJSONObject()));
        jws.sign(signer);
        return jws;
    }

}
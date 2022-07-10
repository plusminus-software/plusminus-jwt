package software.plusminus.jwt.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import software.plusminus.security.Security;

import java.security.PrivateKey;
import java.time.OffsetDateTime;
import java.util.Date;

@Component
public class NimbusJwtGenerator implements JwtGenerator {

    private static final int JWT_EXPIRATION_YEARS = 100;

    @Autowired
    private PrivateKey privateKey;
    @Autowired
    private IssuerService issuerService;

    @Override
    public String generateAccessToken(Security security) {
        JWSSigner signer = new RSASSASigner(privateKey);
        OffsetDateTime issuedAt = OffsetDateTime.now();
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .subject(security.getUsername())
                .issuer(issuerService.currentIssuer())
                .issueTime(Date.from(issuedAt.toInstant()))
                .expirationTime(Date.from(issuedAt.plusYears(JWT_EXPIRATION_YEARS)
                                .toInstant()))
                .claim("roles", security.getRoles());
        security.getOthers().forEach(claimsSetBuilder::claim);
        SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetBuilder.build());
        try {
            signedJwt.sign(signer);
        } catch (JOSEException e) {
            throw new SecurityException(e);
        }
        return signedJwt.serialize();
    }
}

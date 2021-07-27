package software.plusminus.jwt.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class CryptographyConfig {

    @Value("#{environment.JWT_PRIVATE_KEY}")
    private String privateKeyPem;

    @Value("#{environment.JWT_PUBLIC_KEY}")
    private String publicKeyPem;

    @Bean
    public PrivateKey privateKey() throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {

        String key = privateKeyPem.replaceAll("\\n", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll(" ", "")
                .trim();
        PKCS8EncodedKeySpec keySpecPkcs8 = new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(key));
        return keyFactory().generatePrivate(keySpecPkcs8);
    }

    @Bean
    public RSAPublicKey publicKey() throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {

        String key = publicKeyPem.replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll(" ", "")
                .trim();

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(
                Base64.getDecoder().decode(key));
        return (RSAPublicKey) keyFactory().generatePublic(keySpecX509);
    }

    @Bean
    public KeyFactory keyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance("RSA");
    }
}

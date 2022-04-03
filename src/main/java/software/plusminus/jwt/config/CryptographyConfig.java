package software.plusminus.jwt.config;

import org.apache.commons.io.IOUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.fasterxml.jackson.core.JsonEncoding.UTF8;

@Configuration
public class CryptographyConfig {

    @Bean
    public PrivateKey privateKey(JwtProperties jwtProperties) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {

        try (InputStream is = jwtProperties.getPrivateKey().getInputStream()) {
            String key = getKey(is);
            PKCS8EncodedKeySpec keySpecPkcs8 = new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(key));
            return keyFactory().generatePrivate(keySpecPkcs8);
        }
    }

    @Bean
    public RSAPublicKey publicKey(JwtProperties jwtProperties) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {

        try (InputStream is = jwtProperties.getPublicKey().getInputStream()) {
            String key = getKey(is);
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(
                    Base64.getDecoder().decode(key));
            return (RSAPublicKey) keyFactory().generatePublic(keySpecX509);
        }
    }

    @Bean
    public KeyFactory keyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance("RSA");
    }

    private String getKey(InputStream is) throws IOException {
        return IOUtils.toString(is, UTF8.getJavaName())
                .replace("\n", "")
                .replace("\r", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
    }
}

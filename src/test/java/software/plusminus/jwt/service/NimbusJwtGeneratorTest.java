package software.plusminus.jwt.service;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import software.plusminus.security.Security;
import software.plusminus.test.IntegrationTest;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

public class NimbusJwtGeneratorTest extends IntegrationTest {

    @Autowired
    private NimbusJwtGenerator generator;

    @Test
    public void generate_ReturnsGeneratedToken() {
        //given
        Security security = Security.builder()
                .username("some_username")
                .roles(Stream.of("role1", "role2")
                        .collect(Collectors.toSet()))
                .build();
        //when
        String token = generator.generateAccessToken(security);
        //then
        assertThat(token).isNotNull();
    }

}
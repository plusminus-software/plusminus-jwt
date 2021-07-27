package software.plusminus.jwt.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import software.plusminus.authentication.AuthenticationParameters;

import java.io.IOException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest
public class NimbusJwtGeneratorTest {

    @Autowired
    private NimbusJwtGenerator generator;

    @Test
    public void generate_ReturnsGeneratedToken() throws IOException {
        //given
        AuthenticationParameters permission = new AuthenticationParameters();
        permission.setUsername("some_username");
        permission.setRoles(Stream.of("role1", "role2")
                .collect(Collectors.toSet()));
        //when
        String token = generator.generateAccessToken(permission);
        //then
        assertThat(token).isNotNull();
    }

}
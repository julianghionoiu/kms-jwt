package ro.ghionoiu.kmsjwt;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import io.jsonwebtoken.Claims;
import org.junit.BeforeClass;
import org.junit.Test;
import ro.ghionoiu.kmsjwt.key.KMSDecrypt;
import ro.ghionoiu.kmsjwt.key.KMSEncrypt;
import ro.ghionoiu.kmsjwt.token.JWTDecoder;
import ro.ghionoiu.kmsjwt.token.JWTEncoder;

import java.util.Collections;
import java.util.Optional;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class End2EndTest {
    private static final String TEST_AWS_REGION = Optional.ofNullable(System.getenv("TEST_AWS_REGION"))
            .orElse("eu-west-2");

    private static final String TEST_AWS_KEY_ARN = Optional.ofNullable(System.getenv("TEST_AWS_KEY_ARN"))
            .orElse("arn:aws:kms:eu-west-2:577770582757:key/7298331e-c199-4e15-9138-906d1c3d9363");

    private static AWSKMS KMS_CLIENT;

    @BeforeClass
    public static void setUp() throws Exception {
        KMS_CLIENT = AWSKMSClientBuilder.standard()
                .withRegion(TEST_AWS_REGION)
                .build();
    }

    @Test
    public void sign_token_with_KMS_and_verify() throws Exception {
        KMSEncrypt kmsEncrypt = new KMSEncrypt(KMS_CLIENT, TEST_AWS_KEY_ARN);
        KMSDecrypt kmsDecrypt = new KMSDecrypt(KMS_CLIENT, Collections.singleton(TEST_AWS_KEY_ARN));

        String jwt = JWTEncoder.builder(kmsEncrypt)
                .claim("usr", "friendly_name")
                .compact();
        System.out.println("jwt: "+jwt);

        Claims claims = new JWTDecoder(kmsDecrypt).decodeAndVerify(jwt);
        assertThat(claims.get("usr"), is("friendly_name"));
    }
}

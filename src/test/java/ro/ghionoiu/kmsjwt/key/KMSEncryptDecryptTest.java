package ro.ghionoiu.kmsjwt.key;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.xml.bind.DatatypeConverter;
import java.util.Collections;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class KMSEncryptDecryptTest {
    private static final String TEST_AWS_REGION = Optional.ofNullable(System.getenv("TEST_AWS_REGION"))
            .orElse("eu-west-2");

    private static final String TEST_AWS_KEY_ARN = Optional.ofNullable(System.getenv("TEST_AWS_KEY_ARN"))
            .orElse("arn:aws:kms:eu-west-2:577770582757:key/7298331e-c199-4e15-9138-906d1c3d9363");

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private static AWSKMS KMS_CLIENT;

    @BeforeClass
    public static void setUp() throws Exception {
        KMS_CLIENT = AWSKMSClientBuilder.standard()
                .withRegion(TEST_AWS_REGION)
                .build();
    }

    @Test
    public void encrypt_decrypt_work_together() throws Exception {
        KMSEncrypt kmsEncrypt = new KMSEncrypt(KMS_CLIENT, TEST_AWS_KEY_ARN);
        KMSDecrypt kmsDecrypt = new KMSDecrypt(KMS_CLIENT, Collections.singleton(TEST_AWS_KEY_ARN));
        String originalCleartext = "secret";

        String base64CipherText = DatatypeConverter.printBase64Binary(kmsEncrypt.encrypt(originalCleartext.getBytes()));
        System.out.println("ciphertext: "+ base64CipherText);

        String plaintext = new String(kmsDecrypt.decrypt(DatatypeConverter.parseBase64Binary(base64CipherText)));
        System.out.println("plaintext: "+ plaintext);

        assertThat(plaintext, is(originalCleartext));
    }

    @Test
    public void decrypt_should_reject_ciphertext_with_unrecognised_key() throws Exception {
        byte[] ciphertext = new KMSEncrypt(KMS_CLIENT, TEST_AWS_KEY_ARN).encrypt("secret".getBytes());
        KMSDecrypt kmsDecrypt = new KMSDecrypt(KMS_CLIENT, Collections.singleton("SOME_OTHER_KEY"));

        expectedException.expect(KeyOperationException.class);
        expectedException.expectMessage(containsString("signed by unexpected key"));
        kmsDecrypt.decrypt(ciphertext);
    }

    @Test
    public void decrypt_should_reject_ciphertext_if_KMS_returns_exception() throws Exception {
        KMSDecrypt kmsDecrypt = new KMSDecrypt(KMS_CLIENT, Collections.singleton(TEST_AWS_KEY_ARN));

        expectedException.expect(KeyOperationException.class);
        expectedException.expectMessage(containsString("validation error"));
        kmsDecrypt.decrypt(new byte[0]);
    }

    @Test
    public void encrypt_should_stop_encryption_if_KMS_returns_exception() throws Exception {
        expectedException.expect(KeyOperationException.class);
        expectedException.expectMessage(containsString("Invalid keyId"));
        new KMSEncrypt(KMS_CLIENT, "SOME_OTHER_KEY").encrypt("secret".getBytes());
    }

}

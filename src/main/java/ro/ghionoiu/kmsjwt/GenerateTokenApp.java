package ro.ghionoiu.kmsjwt;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import lombok.extern.slf4j.Slf4j;
import ro.ghionoiu.kmsjwt.key.KMSEncrypt;
import ro.ghionoiu.kmsjwt.key.KeyOperationException;
import ro.ghionoiu.kmsjwt.token.JWTEncoder;
import ro.ghionoiu.kmsjwt.token.JWTVerificationException;

@Slf4j
public class GenerateTokenApp {
    @Parameter(names = {"-r", "--region"}, description = "The region where the bucket lives", required = true)
    private String region;

    @Parameter(names = {"-k", "--key"}, description = "The ARN of the key to be used", required = true)
    private String keyARN;

    @Parameter(names = {"-u", "--username"}, description = "Unique username. Should not contain names.", required = true)
    private String username;

    @Parameter(names = {"-j", "--journey"}, description = "The journey associated to this user", required = true)
    private String journey;


    public static void main(String[] args) throws JWTVerificationException, KeyOperationException {
        GenerateTokenApp main = new GenerateTokenApp();
        new JCommander(main, args);

        String jwt = main.generateJWT();
        System.out.println("~~~~~~~~~~~~ JWT ~~~~~~~~~~~~~");
        System.out.println(jwt);
    }

    private String generateJWT() throws KeyOperationException {
        log.info("Generating JWT for user \"{}\" with journey \"{}\"", username, journey);

        AWSKMS kmsClient = AWSKMSClientBuilder.standard()
                .withRegion(region)
                .build();

        KMSEncrypt kmsEncrypt = new KMSEncrypt(kmsClient, keyARN);

        return JWTEncoder.builder(kmsEncrypt)
                .claim("usr", username)
                .claim("jrn", journey)
                .compact();
    }
}

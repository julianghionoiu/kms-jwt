import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.MacProvider;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class SignTest {


    @Test
    public void encode_and_decode() throws Exception {

        long startTime = System.currentTimeMillis();

        SecretKey secretKey = MacProvider.generateKey(SignatureAlgorithm.HS256);
        System.out.println("key: " + base64encode(secretKey));
        String encrypt = encrypt(base64encode(secretKey));
        System.out.println("encrypt(key): " + encrypt);
        String jwt = Jwts.builder()
                .setHeaderParam("kid", encrypt)
                .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .claim("usr", "friendly_name")
                .claim("jrn", "SUM,UPR,HLO")
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
        System.out.println(jwt);

        long afterSigning = System.currentTimeMillis();
        System.out.println("to_sign:" + (afterSigning - startTime));

        Claims claims = Jwts.parser()
                .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                    @Override
                    public Key resolveSigningKey(JwsHeader header, Claims claims) {
                        String base64Key = decrypt(header.getKeyId());
                        System.out.println("Signing key = "+base64Key);
                        return new SecretKeySpec(base64decode(base64Key), SignatureAlgorithm.HS256.getJcaName());
                    }
                })
                .setAllowedClockSkewSeconds(60)
                .parseClaimsJws(jwt)
                .getBody();

        System.out.println(claims.get("usr"));
        System.out.println(claims.get("jrn"));


        long afterValidation = System.currentTimeMillis();
        System.out.println("to_validate:" + (afterValidation - afterSigning));
    }

    private String base64encode(SecretKey secretKey) {
        return DatatypeConverter.printBase64Binary(secretKey.getEncoded());
    }

    private byte[] base64decode(String base64Binary) {
        return DatatypeConverter.parseBase64Binary(base64Binary);
    }


    private String encrypt(String plaintext) {
        return "X" + plaintext + "X";
    }

    private String decrypt(String cypertext) {
        return cypertext.substring(1, cypertext.length() - 1);
    }

}

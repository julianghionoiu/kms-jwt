package ro.ghionoiu.kmsjwt.token;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import ro.ghionoiu.kmsjwt.key.KeyEncrypt;
import ro.ghionoiu.kmsjwt.key.KeyOperationException;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public final class JWTEncoder {

    private JWTEncoder() {
        //Utility class
    }

    public static JwtBuilder builder(KeyEncrypt keyEncrypt) throws KeyOperationException {
        SecretKey secretKey = MacProvider.generateKey(SignatureAlgorithm.HS256);
        byte[] encryptedKey = keyEncrypt.encrypt(secretKey.getEncoded());

        return Jwts.builder()
                .setHeaderParam("kid", DatatypeConverter.printBase64Binary(encryptedKey))
                .signWith(SignatureAlgorithm.HS256, secretKey);
    }

}

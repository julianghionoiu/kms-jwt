package ro.ghionoiu.kmsjwt;

import io.jsonwebtoken.Claims;
import ro.ghionoiu.kmsjwt.key.DummyKeyObfuscation;
import ro.ghionoiu.kmsjwt.token.JWTDecoder;
import ro.ghionoiu.kmsjwt.token.JWTEncoder;
import ro.ghionoiu.kmsjwt.token.JWTVerificationException;

public class App {

    public static void main(String[] args) throws JWTVerificationException {
        String jwt = JWTEncoder.builder(new DummyKeyObfuscation())
                .claim("usr", "friendly_name")
                .compact();

        Claims claims = new JWTDecoder(new DummyKeyObfuscation())
                .decodeAndVerify(jwt);
        System.out.println("usr: "+claims.get("usr"));
    }
}

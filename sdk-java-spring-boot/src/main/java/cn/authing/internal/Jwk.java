package cn.authing.internal;

import com.alibaba.fastjson.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;

public class Jwk {

    private static final Logger logger = LoggerFactory.getLogger(Jwk.class);

    private static class Key {
        private String n;
        private String e;

        public String getN() {
            return n;
        }

        public void setN(String n) {
            this.n = n;
        }

        public String getE() {
            return e;
        }

        public void setE(String e) {
            this.e = e;
        }
    }

    private ArrayList<Key> keys;
    private ArrayList<PublicKey> publicKey;

    static Jwk create(String url) {
        try {
            URL obj = new URL(url);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
            con.setConnectTimeout(10000);
            int code = con.getResponseCode();
            if (code == HttpURLConnection.HTTP_OK) {
                String res = Util.getStringFromStream(con.getInputStream());
                Jwk jwk = JSON.parseObject(res, Jwk.class);
                jwk.generatePublicKey();
                return jwk;
            } else {
                logger.error("init Jwk failed. jwks endpoint:" + url + " status code:" + code);
            }
        } catch (Exception e) {
            logger.error("init Jwk failed. jwks endpoint:" + url);
        }
        return null;
    }

    private void generatePublicKey() {
        if (keys == null || keys.size() == 0) {
            return;
        }

        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        publicKey = new ArrayList<>();

        for (Key key : keys) {
            try {
                String n = key.getN();
                String e = key.getE();
                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
                publicKey.add(keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent)));
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }
    }

    public ArrayList<Key> getKeys() {
        return keys;
    }

    public void setKeys(ArrayList<Key> keys) {
        this.keys = keys;
    }

    static DecodedJWT verifyToken(String idToken, Jwk jwk, String appSecret) {
        if (idToken == null || jwk == null || jwk.publicKey == null) {
            return null;
        }

        DecodedJWT jwt = JWT.decode(idToken);
        if ("HS256".equalsIgnoreCase(jwt.getAlgorithm())) {
            try {
                Algorithm algorithm = Algorithm.HMAC256(appSecret);
                algorithm.verify(jwt);
                return jwt;
            } catch (SignatureVerificationException e) {
                return null;
            }
        } else {
            for (int i = 0; i < jwk.publicKey.size(); ++i) {
                try {
                    if ("RS256".equalsIgnoreCase(jwt.getAlgorithm())) {
                        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.publicKey.get(i), null);
                        algorithm.verify(jwt);
                    }
                    return jwt;
                } catch (SignatureVerificationException e) {
                    continue;
                }
            }
        }
        return null;
    }
}

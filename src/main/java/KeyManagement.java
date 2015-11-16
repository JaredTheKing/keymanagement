import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;
import sun.nio.cs.StandardCharsets;

import java.io.*;
import java.security.PrivateKey;
import java.security.SecureRandom;

public class KeyManagement {

    String encrypt(PrivateKey key, String password) {

        JceOpenSSLPKCS8EncryptorBuilder builder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);

        builder.setRandom(new SecureRandom());

        builder.setPasssword(password.toCharArray());

        try {

            OutputEncryptor outputEncryptor = builder.build();

            JcaPKCS8Generator generator = new JcaPKCS8Generator(key, outputEncryptor);

            PemObject obj = generator.generate();

            return obj.toString();

        }
        catch (Exception exception) {

            System.out.println(exception.getMessage());

            return null;

        }

    }

    String decrypt(String encrypted, String password) {

        JceOpenSSLPKCS8DecryptorProviderBuilder builder = new JceOpenSSLPKCS8DecryptorProviderBuilder();

        try {

            InputDecryptorProvider provider = builder.build(password.toCharArray());

            InputDecryptor inputDecryptor = provider.get(new AlgorithmIdentifier(PKCS8Generator.PBE_SHA1_3DES));

            InputStream encryptedStream = new ByteArrayInputStream(encrypted.getBytes());

            InputStream decryptedInputStream = inputDecryptor.getInputStream(encryptedStream);

            int size = decryptedInputStream.available();

            byte[] bytes = new byte[size];

            decryptedInputStream.read(bytes, 0, size);

            String decrypted = new String(bytes);

            return decrypted;

        }
        catch (Exception exception) {

            System.out.println(exception.getMessage());

            return null;

        }

    }

}

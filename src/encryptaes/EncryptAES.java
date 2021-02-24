package encryptaes;
import java.util.Scanner;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptAES implements Serializable {
//Claves generadas con norton password generator para encriptar y desencriptar
    private static final String secretKeyAES = "Cr6@l*t6W-BodroStof==clbrabu!+u3";
    private static final String saltAES = "NoREcr#-rl7o+8d8Sp7_0P_0@RAGuHes";
//variables privadas para que sean inaccesibles  
    SecretKey secretKeyTemp;
    public EncryptAES() {
        SecretKeyFactory secretkeyfactory;
        
        KeySpec keySpec;
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            //PBKDF2WithHmacSHA256 == PBKDF2 funcion de derivación de claves para 
            //reducir la vulnerabilidad de ataques con fuerza bruta con Hmac (código de autentificacion)
            //SHA256 algoritmo de encriptación 
            keySpec = new PBEKeySpec(secretKeyAES.toCharArray(), saltAES.getBytes(), 65536, 256);
            //PBE encriptci´n basada en password -- 65536 numero de veces que va a iterar
            //256 la longitud d ela cadena
            secretKeyTemp = secretKeyFactory.generateSecret(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public String getAES(String data) {
        try {
            byte[] iv = new byte[16];
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKey = new SecretKeySpec(secretKeyTemp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes("UTF-8")));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public String getAESDecrypt(String data) {
        byte[] iv = new byte[16];
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(secretKeyAES.toCharArray(), saltAES.getBytes(), 65536, 256);
            SecretKey secretKeyTemp = secretKeyFactory.generateSecret(keySpec);
            SecretKeySpec secretKey = new SecretKeySpec(secretKeyTemp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static void main(String[] args) {
        EncryptAES encrypt = new EncryptAES();
        Scanner sc = new Scanner(System.in);
        System.out.println("Palabra a encriptar:" );
        String data = sc.nextLine();
        System.out.println("Datos encriptados: " + encrypt.getAES(data));
        System.out.println("Copie el código de la parte superior para poder desencriptarlo");
        System.out.println("Ingrese código de desencriptación: ");
        String code = sc.nextLine();
        System.out.println("Datos desencriptados: " + encrypt.getAESDecrypt(code));
    }
    
}
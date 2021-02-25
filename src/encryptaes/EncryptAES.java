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
                    //Instanciamos una clase SecretKeyFactory con el nombre del algoritmo que necesitamos 
            //es una fábrica de claves secretas
        KeySpec keySpec;
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            //PBKDF2WithHmacSHA256 == PBKDF2 funcion de derivación de claves para 
            //reducir la vulnerabilidad de ataques con fuerza bruta con Hmac (código de autentificacion)
            //SHA256 algoritmo de encriptación 
            keySpec = new PBEKeySpec(secretKeyAES.toCharArray(), saltAES.getBytes(), 65536, 256);
            //PBE encriptción basada en password -- 65536 numero de veces que va a iterar
            //256 la longitud d ela cadena
            secretKeyTemp = secretKeyFactory.generateSecret(keySpec);
            //Creamos una SecretKey usando la clase SecretKeyFactory y pasando el cifrado basado en contraseña (PBEKeySpec)
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public String getAES(String data) {
        try {
            //vector de bloque de 16 bytes
            byte[] iv = new byte[16];
//Luego inicializamos una clase IvParameterSpec que simplemente especifica el vector de inicialización a usar.
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            //Inicializamos una clase SecretKeySpec (especifica una clave secreta de forma independiente 
    //del proveedor) pasando como parámetro la clave anterior generada en forma de bytes 
    //y el algoritmo que usamos.
            SecretKeySpec secretKey = new SecretKeySpec(secretKeyTemp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
    //Finalmente hacemos uso de la clase Cipher del paquete crypto que proporciona la funcionalidad de 
    //un cifrado criptográfico para cifrado y descifrado, obtenemos la instancia del algoritmo, 
    //después usamos el método init con el modo ya sea descifrado o cifrado, la especificación 
    //de la llave secreta y la especificación del vector de inicialización
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
        System.out.println("Ingrese texto a encriptar:" );
        String data = sc.nextLine();
        System.out.println("==============================================");
        System.out.println("Datos encriptados: \n" + encrypt.getAES(data));
        System.out.println("==============================================");
        System.out.println("Copie el código generado de la parte  \nsuperior para poder desencriptarlo");
        System.out.println("==============================================");
        System.out.println("Ingrese código a desencriptar: ");
        String code = sc.nextLine();
        System.out.println("Datos desencriptados:\n" + "---- " + encrypt.getAESDecrypt(code) + " ----");
    }
    
}

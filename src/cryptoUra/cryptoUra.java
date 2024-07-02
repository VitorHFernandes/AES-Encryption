package cryptoUra;
import org.apache.commons.codec.binary.Base32;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.io.IOException;
import java.util.Scanner;

public class cryptoUra {

    private static final int IV_SIZE_BYTES = 16;
    private static final int INT_SIZE = 4;
    private static final int GCM_TAG_LENGTH = 128;

    private static Cipher initChiper(final int mode, final byte[] salt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
    //	Properties prop = new Properties();
    //	FileInputStream file = new FileInputStream("./properties/conf.properties");
    //	prop.load(file);
    	
  //      final String secretKey = prop.getProperty("CARD_ID_SECRET_KEY");
    	final String secretKey = "ByTUsBW4IwCtEMa8";
        final SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, salt);
        cipher.init(mode, secretKeySpec, parameterSpec);

        return cipher;
    }

    public static String encrypt(final String cardNumber) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        final byte[] salt = genIv();
        final Cipher cipher = initChiper(Cipher.ENCRYPT_MODE, salt);

        byte[] cipherText = cipher.doFinal(cardNumber.getBytes(StandardCharsets.UTF_8));

        ByteBuffer byteBuffer = ByteBuffer.allocate(INT_SIZE + IV_SIZE_BYTES + cipherText.length);
        byteBuffer.putInt(IV_SIZE_BYTES);
        byteBuffer.put(salt);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();

        return new Base32().encodeAsString(cipherMessage);
    }

    public static String decrypt(String encryptedCardNumber) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        final byte[] decodedCardId = new Base32().decode(URLDecoder.decode(encryptedCardNumber, StandardCharsets.UTF_8.name()));
        final ByteBuffer buffer = ByteBuffer.wrap(decodedCardId);
        final int ivLength = buffer.getInt();
        final byte[] salt = new byte[ivLength];
        buffer.get(salt);
        final byte[] cipherText = new byte[buffer.remaining()];
        buffer.get(cipherText);

        final Cipher cipher = initChiper(Cipher.DECRYPT_MODE, salt);

        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    private static byte[] genIv() {
        final byte[] iv = new byte[IV_SIZE_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
    	Scanner sc = new Scanner(System.in);
    	System.out.printf("");
    	String cardNumber = args[0];//sc.nextLine();
    	sc.close();
    //	String cardNumber = "4180721200354400";
    	System.out.println(encrypt(cardNumber));
    }

}

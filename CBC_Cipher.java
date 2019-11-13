package AES_Ciphers; 

import java.security.Key;
import javax.crypto.Cipher;

public class CBC_Cipher {
    
    private static final int BLOCK_LENGTH = 16; 

    private static byte[] encryptWithECB(byte[] text, Key key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        System.out.println(cipher.getBlockSize());

        byte[] result = cipher.doFinal(text);

        // System.out.println(result.length);
        
        return result; 
    }

    private static byte[] decryptWithECB(byte[] text, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(text);
    }

    public static byte xor(byte x, byte y) {
        int xInt = (int) x; 
        int yInt = (int) y; 

        int result = xInt^yInt; 
        return (byte)(0xff & result); 
    }

    public static byte[] xor(byte[] x, byte[] y) {
        byte[] result = new byte[x.length]; 
        for (int i = 0; i < x.length; i++) {
            result[i] = xor(x[i], y[i]); 
        }

        // System.out.println(x.length);
        // System.out.println(y.length);

        return result; 
    }

    private static byte[] getBlock(int startIndex, byte[] bytes) {
        byte[] result = new byte[BLOCK_LENGTH]; 

        for (int i = 0; i + startIndex < bytes.length && i < BLOCK_LENGTH; i++) {
            result[i] = bytes[startIndex + i]; 
        }

        return result; 
    }

    public static String encrypt(String text, Key key, String initVector) throws Exception {
        byte[] textBytes = text.getBytes();
        byte[] lastBlock = initVector.getBytes();

        byte[] result = new byte[text.length()]; 

        for (int i = 0; i < textBytes.length; i+=BLOCK_LENGTH) {
            byte[] block = getBlock(i, textBytes); 
            lastBlock = encryptWithECB(xor(block, lastBlock), key); 

            for (int j = i; j < i + BLOCK_LENGTH; j++) {
                result[j] = lastBlock[j-i]; 
            }

        }

        return new String(result); 
    }

    public static String decrypt(String text, Key key, String initVector) throws Exception {
        byte[] textBytes = text.getBytes();
        byte[] lastBlock = initVector.getBytes();

        System.out.println(lastBlock.length);

        byte[] result = new byte[text.length()]; 

        for (int i = 0; i < textBytes.length; i+=BLOCK_LENGTH) {
            byte[] block = getBlock(i, textBytes); 
            lastBlock = xor(decryptWithECB(block, key), lastBlock); 

            for (int j = i; j < i + BLOCK_LENGTH; j++) {
                result[j] = lastBlock[j-i]; 
            }

        }

        return new String(result); 
    }
}
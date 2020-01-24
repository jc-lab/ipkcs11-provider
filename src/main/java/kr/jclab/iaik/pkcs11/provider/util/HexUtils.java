package kr.jclab.iaik.pkcs11.provider.util;

public class HexUtils {
    private static final String HEX_CHARS = "0123456789abcdef";

    private static char decToHex(int d) {
        return HEX_CHARS.charAt(d & 0xf);
    }

    public static String bytesToHex(byte[] input) {
        StringBuilder stringBuilder = new StringBuilder();
        for(byte b : input) {
            stringBuilder.append(decToHex(b >> 4));
            stringBuilder.append(decToHex(b));
        }
        return stringBuilder.toString();
    }
}

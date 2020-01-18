package kr.jclab.iaik.pkcs11.provider.util;

import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.LongAttribute;
import kr.jclab.iaik.pkcs11.provider.AlgorithmConstants;

public class Pkcs11KeyUtils {
    public static String getAlgorithm(Key p11Key) {
        LongAttribute attribute = p11Key.getKeyType();

        if(!attribute.isPresent())
            return null;

        Long value = attribute.getLongValue();
        if(Key.KeyType.EC.equals(value)) {
            return AlgorithmConstants.EC;
        }else if(Key.KeyType.EC_EDWARDS.equals(value)) {
            return AlgorithmConstants.EC;
        }else if(Key.KeyType.EC_MONTGOMERY.equals(value)) {
            return AlgorithmConstants.EC;
        }else if(Key.KeyType.RSA.equals(value)) {
            return AlgorithmConstants.RSA;
        }else if(Key.KeyType.DSA.equals(value)) {
            return AlgorithmConstants.DSA;
        }else{
            return null;
        }
    }
}

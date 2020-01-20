package kr.jclab.iaik.pkcs11.provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

public class SingletoneBouncyCastle {
    public static Provider getInstance() {
        return SingletoneHolder.INSTANCE;
    }

    private static class SingletoneHolder {
        private final static Provider INSTANCE = new BouncyCastleProvider();
    }
}

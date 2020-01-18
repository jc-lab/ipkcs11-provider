package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

public class WrappedRSAPrivateKey extends WrappedPrivateKey implements RSAPrivateKey {
    private final iaik.pkcs.pkcs11.objects.RSAPrivateKey p11PrivateKey;
    private final BigInteger modulus;

    public WrappedRSAPrivateKey(iaik.pkcs.pkcs11.objects.RSAPrivateKey p11PrivateKey) {
        super();
        this.p11PrivateKey = p11PrivateKey;
        this.modulus = new BigInteger(p11PrivateKey.getModulus().getByteArrayValue());
    }

    @Override
    public iaik.pkcs.pkcs11.objects.PrivateKey getP11PrivateKey() {
        return this.p11PrivateKey;
    }

    @Override
    public BigInteger getPrivateExponent() {
        return null;
    }

    @Override
    public BigInteger getModulus() {
        return this.modulus;
    }
}

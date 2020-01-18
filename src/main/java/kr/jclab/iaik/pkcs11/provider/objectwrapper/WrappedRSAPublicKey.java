package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class WrappedRSAPublicKey extends WrappedPublicKey implements RSAPublicKey {
    private final iaik.pkcs.pkcs11.objects.RSAPublicKey p11PublicKey;
    private final BigInteger publicExponent;
    private final BigInteger modulus;

    public WrappedRSAPublicKey(iaik.pkcs.pkcs11.objects.RSAPublicKey p11PublicKey) {
        super();
        this.p11PublicKey = p11PublicKey;
        this.publicExponent = new BigInteger(p11PublicKey.getPublicExponent().getByteArrayValue());
        this.modulus = new BigInteger(p11PublicKey.getModulus().getByteArrayValue());
    }

    @Override
    public iaik.pkcs.pkcs11.objects.PublicKey getP11PublicKey() {
        return this.p11PublicKey;
    }

    @Override
    public BigInteger getPublicExponent() {
        return this.publicExponent;
    }

    @Override
    public BigInteger getModulus() {
        return this.modulus;
    }
}

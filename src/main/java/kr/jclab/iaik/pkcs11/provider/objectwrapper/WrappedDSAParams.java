package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

public class WrappedDSAParams implements DSAParams {
    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;

    public static WrappedDSAParams fromByteArray(byte[] p, byte[] q, byte[] g) {
        return new WrappedDSAParams(
                new BigInteger(p),
                new BigInteger(q),
                new BigInteger(g)
        );
    }

    public WrappedDSAParams(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    @Override
    public BigInteger getP() {
        return this.p;
    }

    @Override
    public BigInteger getQ() {
        return this.q;
    }

    @Override
    public BigInteger getG() {
        return this.g;
    }
}

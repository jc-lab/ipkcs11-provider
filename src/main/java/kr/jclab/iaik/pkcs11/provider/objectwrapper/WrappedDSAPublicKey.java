package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import iaik.pkcs.pkcs11.objects.PublicKey;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

public class WrappedDSAPublicKey extends WrappedPublicKey implements DSAPublicKey {
    private final iaik.pkcs.pkcs11.objects.DSAPublicKey p11PublicKey;
    private final DSAParams params;
    private final BigInteger y;

    public WrappedDSAPublicKey(iaik.pkcs.pkcs11.objects.DSAPublicKey p11PublicKey) {
        super();
        this.p11PublicKey = p11PublicKey;
        this.params = WrappedDSAParams.fromByteArray(
                p11PublicKey.getPrime().getByteArrayValue(),
                p11PublicKey.getSubprime().getByteArrayValue(),
                p11PublicKey.getBase().getByteArrayValue()
        );
        this.y = new BigInteger(p11PublicKey.getValue().getByteArrayValue());
    }

    @Override
    public iaik.pkcs.pkcs11.objects.PublicKey getP11PublicKey() {
        return this.p11PublicKey;
    }

    @Override
    public BigInteger getY() {
        return this.y;
    }

    @Override
    public DSAParams getParams() {
        return this.params;
    }
}

package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import kr.jclab.iaik.pkcs11.provider.util.Pkcs11KeyUtils;

import javax.security.auth.DestroyFailedException;
import java.security.PrivateKey;

public class WrappedPrivateKey implements PrivateKey {
    private final iaik.pkcs.pkcs11.objects.PrivateKey p11PrivateKey;

    protected WrappedPrivateKey() {
        this.p11PrivateKey = null;
    }

    public WrappedPrivateKey(iaik.pkcs.pkcs11.objects.PrivateKey p11PrivateKey) {
        if(p11PrivateKey == null)
            throw new NullPointerException();
        this.p11PrivateKey = p11PrivateKey;
    }

    public static WrappedPrivateKey from(iaik.pkcs.pkcs11.objects.PrivateKey p11PrivateKey) {
        if(p11PrivateKey instanceof iaik.pkcs.pkcs11.objects.RSAPrivateKey) {
            return new WrappedRSAPrivateKey((iaik.pkcs.pkcs11.objects.RSAPrivateKey)p11PrivateKey);
        }else if(p11PrivateKey instanceof iaik.pkcs.pkcs11.objects.DSAPrivateKey) {
            return new WrappedDSAPrivateKey((iaik.pkcs.pkcs11.objects.DSAPrivateKey)p11PrivateKey);
        }else if(p11PrivateKey instanceof iaik.pkcs.pkcs11.objects.ECPrivateKey) {
            return new WrappedECPrivateKey((iaik.pkcs.pkcs11.objects.ECPrivateKey)p11PrivateKey);
        }else{
            return new WrappedPrivateKey(p11PrivateKey);
        }
    }

    public iaik.pkcs.pkcs11.objects.PrivateKey getP11PrivateKey() {
        return this.p11PrivateKey;
    }

    @Override
    public String getAlgorithm() {
        return Pkcs11KeyUtils.getAlgorithm(this.getP11PrivateKey());
    }

    @Override
    public String getFormat() {
        return "PKCS11";
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public void destroy() throws DestroyFailedException {

    }

    @Override
    public boolean isDestroyed() {
        return false;
    }
}

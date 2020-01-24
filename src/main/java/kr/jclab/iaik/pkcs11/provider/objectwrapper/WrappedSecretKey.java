package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

public class WrappedSecretKey implements SecretKey {
    private final iaik.pkcs.pkcs11.objects.SecretKey p11SecretKey;
    private final String algorithm;

    public WrappedSecretKey(iaik.pkcs.pkcs11.objects.SecretKey p11SecretKey) {
        this.p11SecretKey = p11SecretKey;
        if(p11SecretKey.getKeyType().getLongValue() == PKCS11Constants.CKK_AES) {
            this.algorithm = "AES";
        }else{
            this.algorithm = null;
        }
    }

    public iaik.pkcs.pkcs11.objects.SecretKey getP11SecretKey() {
        return this.p11SecretKey;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public String getFormat() {
        return null;
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

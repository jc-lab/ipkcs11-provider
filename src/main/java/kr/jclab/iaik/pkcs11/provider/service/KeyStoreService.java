package kr.jclab.iaik.pkcs11.provider.service;

import kr.jclab.iaik.pkcs11.provider.JsIaikPkcs11Provider;
import kr.jclab.iaik.pkcs11.provider.keystore.KeyStoreSpiImpl;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public class KeyStoreService extends Provider.Service {
    private final boolean useAliasId;

    public KeyStoreService(Provider provider, String algorithm, boolean useAliasId) {
        super(provider, "KeyStore", algorithm, KeyStoreService.class.getName(), null, null);
        this.useAliasId = useAliasId;
    }

    private JsIaikPkcs11Provider getSelfProvider() {
        return (JsIaikPkcs11Provider)getProvider();
    }

    @Override
    public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
        return new KeyStoreSpiImpl(getSelfProvider(), this.useAliasId);
    }
}

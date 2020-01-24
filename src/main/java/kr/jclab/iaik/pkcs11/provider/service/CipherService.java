package kr.jclab.iaik.pkcs11.provider.service;

import kr.jclab.iaik.pkcs11.provider.JsIaikPkcs11Provider;
import kr.jclab.iaik.pkcs11.provider.cipher.CipherSpiImpl;
import kr.jclab.iaik.pkcs11.provider.cipher.PaddingProvider;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.List;

public class CipherService extends Provider.Service {
    private final Long mechanism;
    private final int fixedBlockSize;
    private final PaddingProvider paddingProvider;

    public CipherService(Provider provider, String algorithm, List<String> aliases, Long mechanism, Integer fixedBlockSize, PaddingProvider paddingProvider) {
        super(provider, "Cipher", algorithm, CipherService.class.getName(), aliases, null);
        this.mechanism = mechanism;
        this.fixedBlockSize = fixedBlockSize;
        this.paddingProvider = paddingProvider;
    }

    @Override
    public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
        return new CipherSpiImpl((JsIaikPkcs11Provider)this.getProvider(), this.mechanism, this.fixedBlockSize, this.paddingProvider);
    }
}

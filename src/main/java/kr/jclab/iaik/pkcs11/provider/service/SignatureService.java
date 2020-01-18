package kr.jclab.iaik.pkcs11.provider.service;

import kr.jclab.iaik.pkcs11.provider.JsIaikPkcs11Provider;
import kr.jclab.iaik.pkcs11.provider.signature.SignatureSpiImpl;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.List;

public class SignatureService extends Provider.Service {
    private final long mechanism;

    public SignatureService(Provider provider, String algorithm, Long mechanism) {
        super(provider, "Signature", algorithm, SignatureService.class.getName(), null, null);
        this.mechanism = mechanism;
    }

    public SignatureService(Provider provider, String algorithm, Long mechanism, List<String> aliases) {
        super(provider, "Signature", algorithm, SignatureService.class.getName(), aliases, null);
        this.mechanism = mechanism;
    }

    private JsIaikPkcs11Provider getSelfProvider() {
        return (JsIaikPkcs11Provider)getProvider();
    }

    @Override
    public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
        return new SignatureSpiImpl(getSelfProvider(), getAlgorithm(), this.mechanism);
    }
}

package kr.jclab.iaik.pkcs11.provider.service;

import kr.jclab.iaik.pkcs11.provider.JsIaikPkcs11Provider;
import kr.jclab.iaik.pkcs11.provider.signature.SignatureSpiImpl;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.List;

public class SignatureService extends Provider.Service {
    private final long mechanism;
    private final String digestAlgorithm;
    private final Long signatureMechanism;

    public SignatureService(Provider provider, String algorithm, String digestAlgorithm, Long signatureMechanism, Long mechanism) {
        super(provider, "Signature", algorithm, SignatureService.class.getName(), null, null);
        this.mechanism = mechanism;
        this.digestAlgorithm = digestAlgorithm;
        this.signatureMechanism = signatureMechanism;
    }

    public SignatureService(Provider provider, String algorithm, String digestAlgorithm, Long signatureMechanism, Long mechanism, List<String> aliases) {
        super(provider, "Signature", algorithm, SignatureService.class.getName(), aliases, null);
        this.mechanism = mechanism;
        this.digestAlgorithm = digestAlgorithm;
        this.signatureMechanism = signatureMechanism;
    }

    private JsIaikPkcs11Provider getSelfProvider() {
        return (JsIaikPkcs11Provider)getProvider();
    }

    @Override
    public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
        return new SignatureSpiImpl(getSelfProvider(), getAlgorithm(), this.digestAlgorithm, this.signatureMechanism, this.mechanism);
    }
}

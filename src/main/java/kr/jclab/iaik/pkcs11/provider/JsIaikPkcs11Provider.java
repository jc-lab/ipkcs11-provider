package kr.jclab.iaik.pkcs11.provider;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import kr.jclab.iaik.pkcs11.provider.service.SignatureService;

import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

public class JsIaikPkcs11Provider extends Provider {
    private final Session session;

    public JsIaikPkcs11Provider(Session session) {
        super("JS_IAIK_PKCS11", 1.0, "JsIaikPkcs11 Provider");

        this.session = session;

        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            setup();
            return null;
        });
    }

    private final static List<String> dsaSignatureSuffixes = Collections.unmodifiableList(Arrays.asList(
            "WITHDSA", "withDSA", "WithDSA", "/DSA"
    ));
    private final static List<String> rsaSignatureSuffixes = Collections.unmodifiableList(Arrays.asList(
            "WITHRSA", "withRSA", "WithRSA", "/RSA", "WITHRSAENCRYPTION", "withRSAEncryption", "WithRSAEncryption"
    ));
    private final static List<String> pssSignatureSuffixes = Collections.unmodifiableList(Arrays.asList(
            "withRSA/PSS", "WithRSA/PSS", "withRSAandMGF1", "WithRSAandMGF1"
    ));

    private void setup() {
        this.putService(new SignatureService(this, "ECDSA", CKM_ECDSA));
        this.putService(new SignatureService(this, "SHA1withECDSA", CKM_ECDSA_SHA1));
        this.putService(new SignatureService(this, "SHA224withECDSA", CKM_ECDSA_SHA224));
        this.putService(new SignatureService(this, "SHA256withECDSA", CKM_ECDSA_SHA256));
        this.putService(new SignatureService(this, "SHA384withECDSA", CKM_ECDSA_SHA384));
        this.putService(new SignatureService(this, "SHA512withECDSA", CKM_ECDSA_SHA512));
        this.putService(new SignatureService(this, "SHA3-224withECDSA", CKM_ECDSA_SHA3_224));
        this.putService(new SignatureService(this, "SHA3-256withECDSA", CKM_ECDSA_SHA3_256));
        this.putService(new SignatureService(this, "SHA3-384withECDSA", CKM_ECDSA_SHA3_384));
        this.putService(new SignatureService(this, "SHA3-512withECDSA", CKM_ECDSA_SHA3_512));

        this.addWithAliases(SignatureService.class, "DSA", CKM_DSA);
        this.addWithSuffixes(SignatureService.class, "SHA1", PKCS11Constants.CKM_DSA_SHA1, dsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA224", PKCS11Constants.CKM_DSA_SHA224, dsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA256", PKCS11Constants.CKM_DSA_SHA256, dsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA384", PKCS11Constants.CKM_DSA_SHA384, dsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA512", PKCS11Constants.CKM_DSA_SHA512, dsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-224", PKCS11Constants.CKM_DSA_SHA3_224, dsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-256", PKCS11Constants.CKM_DSA_SHA3_256, dsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-384", PKCS11Constants.CKM_DSA_SHA3_384, dsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-512", PKCS11Constants.CKM_DSA_SHA3_512, dsaSignatureSuffixes);

        this.addWithAliases(SignatureService.class, "RSA", CKM_RSA_PKCS, Arrays.asList("RAWRSA", "NONEWITHRSA"));
        this.addWithSuffixes(SignatureService.class, "SHA1", PKCS11Constants.CKM_SHA1_RSA_PKCS, rsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA224", PKCS11Constants.CKM_SHA224_RSA_PKCS, rsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA256", PKCS11Constants.CKM_SHA256_RSA_PKCS, rsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA384", PKCS11Constants.CKM_SHA384_RSA_PKCS, rsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA512", PKCS11Constants.CKM_SHA512_RSA_PKCS, rsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-224", PKCS11Constants.CKM_SHA3_224_RSA_PKCS, rsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-256", PKCS11Constants.CKM_SHA3_256_RSA_PKCS, rsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-384", PKCS11Constants.CKM_SHA3_384_RSA_PKCS, rsaSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-512", PKCS11Constants.CKM_SHA3_512_RSA_PKCS, rsaSignatureSuffixes);

        this.addWithAliases(SignatureService.class, "RSASSA-PSS", CKM_RSA_PKCS_PSS, Arrays.asList("RAWRSAPSS", "NONEWITHRSAPSS", "NONEWITHRSASSA-PSS", "NONEWITHRSAANDMGF1", "RSAPSS"));
        this.addWithSuffixes(SignatureService.class, "SHA1", PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA224", PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA256", PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA384", PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA512", PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-224", PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-256", PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-384", PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addWithSuffixes(SignatureService.class, "SHA3-512", PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS, pssSignatureSuffixes);
    }

    private void addWithAliases(Class<? extends Service> clazz, String name, long mechanism, List<String> aliases) {
        try {
            String defaultAlgorithm = (name != null) ? name : aliases.get(0);
            this.putService(clazz
                    .getDeclaredConstructor(Provider.class, String.class, Long.class, List.class)
                    .newInstance(this, defaultAlgorithm, mechanism, aliases));
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    private void addWithAliases(Class<? extends Service> clazz, String name, long mechanism) {
        this.addWithAliases(clazz, name, mechanism, null);
    }

    private void addWithSuffixes(Class<? extends Service> clazz, String name, long mechanism, List<String> suffixes) {
        List<String> aliases = suffixes.stream()
                .map(v -> name + v)
                .collect(Collectors.toList());
        for(String key : aliases) {
            this.addWithAliases(clazz, key, mechanism, null);
        }
    }

    public boolean hasAlgorithm(String type, String name)
    {
        return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
    }

    public void addAlgorithm(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

//    public void addAlgorithm(String type, ASN1ObjectIdentifier oid, String className)
//    {
//        addAlgorithm(type + "." + oid, className);
//        addAlgorithm(type + ".OID." + oid, className);
//    }

    public Session getSession() {
        return this.session;
    }
}

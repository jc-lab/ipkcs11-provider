package kr.jclab.iaik.pkcs11.provider;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import kr.jclab.iaik.pkcs11.provider.cipher.NoPaddingProvider;
import kr.jclab.iaik.pkcs11.provider.cipher.PaddingProvider;
import kr.jclab.iaik.pkcs11.provider.cipher.Pkcs7PaddingProvider;
import kr.jclab.iaik.pkcs11.provider.service.CipherService;
import kr.jclab.iaik.pkcs11.provider.service.KeyStoreService;
import kr.jclab.iaik.pkcs11.provider.service.SignatureService;

import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.*;
import java.util.stream.Collectors;

public class JsIaikPkcs11Provider extends Provider {
    private final Session session;
    private final Set<Long> mechanismSet;

    public JsIaikPkcs11Provider(Session session) {
        super("JS_IAIK_PKCS11", 1.0, "JsIaikPkcs11 Provider");

        this.session = session;
        Set<Long> mechanismSet = null;

        try {
            Set<Long> tempMechanismSet = new HashSet<>();
            for(Mechanism m : this.session.getToken().getMechanismList()) {
                tempMechanismSet.add(m.getMechanismCode());
            }
            mechanismSet = Collections.unmodifiableSet(tempMechanismSet);
        } catch (TokenException e) {
        }

        this.mechanismSet = mechanismSet;

        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            setup();
            return null;
        });
    }

    private final static List<String> ecdsaSignatureSuffixes = Collections.unmodifiableList(Arrays.asList(
            "WITHECDSA", "withECDSA", "WithECDSA", "/ECDSA"
    ));
    private final static List<String> dsaSignatureSuffixes = Collections.unmodifiableList(Arrays.asList(
            "WITHDSA", "withDSA", "WithDSA", "/DSA"
    ));
    private final static List<String> rsaSignatureSuffixes = Collections.unmodifiableList(Arrays.asList(
            "WITHRSA", "withRSA", "WithRSA", "/RSA", "WITHRSAENCRYPTION", "withRSAEncryption", "WithRSAEncryption"
    ));
    private final static List<String> pssSignatureSuffixes = Collections.unmodifiableList(Arrays.asList(
            "withRSA/PSS", "WithRSA/PSS", "withRSAandMGF1", "WithRSAandMGF1"
    ));

    private boolean hasMechanism(long code) {
        if(this.mechanismSet != null) {
            return this.mechanismSet.contains(code);
        }
        return true;
    }

    private void setup() {
        this.addSignatureWithAliases(SignatureService.class, "ECDSA", null, PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA1", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA1, ecdsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA224", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA224, ecdsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA256", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA256, ecdsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA384", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA384, ecdsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA512", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA512, ecdsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-224", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA3_224, ecdsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-256", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA3_256, ecdsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-384", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA3_384, ecdsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-512", PKCS11Constants.CKM_ECDSA, PKCS11Constants.CKM_ECDSA_SHA3_512, ecdsaSignatureSuffixes);

        this.addSignatureWithAliases(SignatureService.class, "DSA", null, PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA1", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA1, dsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA224", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA224, dsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA256", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA256, dsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA384", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA384, dsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA512", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA512, dsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-224", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA3_224, dsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-256", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA3_256, dsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-384", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA3_384, dsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-512", PKCS11Constants.CKM_DSA, PKCS11Constants.CKM_DSA_SHA3_512, dsaSignatureSuffixes);

        this.addSignatureWithAliases(SignatureService.class, "RSA", null, PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_RSA_PKCS, Arrays.asList("RAWRSA", "NONEWITHRSA"));
        this.addSignatureWithSuffixes(SignatureService.class, "SHA1", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA1_RSA_PKCS, rsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA224", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA224_RSA_PKCS, rsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA256", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA256_RSA_PKCS, rsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA384", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA384_RSA_PKCS, rsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA512", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA512_RSA_PKCS, rsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-224", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA3_224_RSA_PKCS, rsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-256", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA3_256_RSA_PKCS, rsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-384", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA3_384_RSA_PKCS, rsaSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-512", PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_SHA3_512_RSA_PKCS, rsaSignatureSuffixes);

        this.addSignatureWithAliases(SignatureService.class, "RSASSA-PSS", null, PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_RSA_PKCS_PSS, Arrays.asList("RAWRSAPSS", "NONEWITHRSAPSS", "NONEWITHRSASSA-PSS", "NONEWITHRSAANDMGF1", "RSAPSS"));
        this.addSignatureWithSuffixes(SignatureService.class, "SHA1", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA224", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA256", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA384", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA512", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-224", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-256", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-384", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS, pssSignatureSuffixes);
        this.addSignatureWithSuffixes(SignatureService.class, "SHA3-512", PKCS11Constants.CKM_RSA_PKCS_PSS, PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS, pssSignatureSuffixes);

        this.putService(new KeyStoreService(this, "PKCS11", false));
        this.putService(new KeyStoreService(this, "PKCS11-ID", true));

        this.addCipher(CipherService.class, new String[] {
                "AES", "AES/ECB/NoPadding"
        }, PKCS11Constants.CKM_AES_ECB, 16, SingletoneHolder.PADDING_NO);

        this.addCipher(CipherService.class, new String[] {
                "AES/ECB/PKCS5Padding", "AES/ECB/PKCS7Padding"
        }, PKCS11Constants.CKM_AES_ECB, 16, SingletoneHolder.PADDING_PKCS7);

        this.addCipher(CipherService.class, new String[] {
                "AES/CBC/NoPadding"
        }, PKCS11Constants.CKM_AES_CBC, 16, SingletoneHolder.PADDING_NO);

        this.addCipher(CipherService.class, new String[]{
                "AES/CBC/PKCS5Padding", "AES/CBC/PKCS7Padding"
        }, PKCS11Constants.CKM_AES_CBC, 16, SingletoneHolder.PADDING_PKCS7);
    }

    private void addSignatureWithAliases(Class<? extends Service> clazz, String name, String digestName, Long signatureMechanism, long mechanism, List<String> aliases) {
        try {
            String defaultAlgorithm = (name != null) ? name : aliases.get(0);
            this.putService(clazz
                    .getDeclaredConstructor(Provider.class, String.class, String.class, Long.class, Long.class, List.class)
                    .newInstance(this, defaultAlgorithm, digestName, signatureMechanism, mechanism, aliases));
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    private void addSignatureWithAliases(Class<? extends Service> clazz, String name, String digestName, Long signatureMechanism, long mechanism) {
        this.addSignatureWithAliases(clazz, name, digestName, signatureMechanism, mechanism, null);
    }

    private void addSignatureWithSuffixes(Class<? extends Service> clazz, String digestName, Long signatureMechanism, long mechanism, List<String> suffixes) {
        List<String> aliases = suffixes.stream()
                .map(v -> digestName + v)
                .collect(Collectors.toList());
        for(String key : aliases) {
            this.addSignatureWithAliases(clazz, key, digestName, signatureMechanism, mechanism, null);
        }
    }

    private void addCipher(Class<? extends Service> clazz, String[] algorithms, Long cipherMechanism, int fixedBlockSize, PaddingProvider paddingProvider) {
        try {
            for(String algo : algorithms) {
                this.putService(clazz
                        .getDeclaredConstructor(Provider.class, String.class, List.class, Long.class, Integer.class, PaddingProvider.class)
                        .newInstance(this, algo, null, cipherMechanism, fixedBlockSize, paddingProvider));
            }
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    public Session getSession() {
        return this.session;
    }

    private static class SingletoneHolder {
        public static final PaddingProvider PADDING_NO = new NoPaddingProvider();
        public static final PaddingProvider PADDING_PKCS7 = new Pkcs7PaddingProvider();
    }
}

package kr.jclab.iaik.pkcs11.provider.keystore;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import kr.jclab.iaik.pkcs11.provider.JsIaikPkcs11Provider;
import kr.jclab.iaik.pkcs11.provider.SingletoneBouncyCastle;
import kr.jclab.iaik.pkcs11.provider.objectwrapper.*;
import kr.jclab.iaik.pkcs11.provider.util.HexUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class KeyStoreSpiImpl extends KeyStoreSpi {
    private final JsIaikPkcs11Provider provider;
    private final boolean useAliasId;

    public KeyStoreSpiImpl(JsIaikPkcs11Provider provider, boolean useAliasId) {
        this.provider = provider;
        this.useAliasId = useAliasId;
    }

    private String toAlias(iaik.pkcs.pkcs11.objects.Storage object) {
        if(this.useAliasId) {
            if(object instanceof iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate) {
                iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate x509Certificate = (iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate)object;
                if(x509Certificate.getId().isPresent() && x509Certificate.getId().getByteArrayValue() != null) {
                    return HexUtils.bytesToHex(x509Certificate.getId().getByteArrayValue());
                }
            }else if(object instanceof iaik.pkcs.pkcs11.objects.Key) {
                iaik.pkcs.pkcs11.objects.Key key = (iaik.pkcs.pkcs11.objects.Key)object;
                return HexUtils.bytesToHex(key.getId().getByteArrayValue());
            }
        }else{
            return new String(object.getLabel().getCharArrayValue());
        }
        return null;
    }

    private boolean equalsAlias(iaik.pkcs.pkcs11.objects.Storage object, String alias) {
        return alias.equalsIgnoreCase(toAlias(object));
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        Session session = this.provider.getSession();
        try {
            session.findObjectsInit(new iaik.pkcs.pkcs11.objects.Key());
            PKCS11Object[] tempObjects;
            iaik.pkcs.pkcs11.objects.Key foundKey = null;
            try {
                do {
                    tempObjects = session.findObjects(1);
                    if (tempObjects.length > 0) {
                        if(tempObjects[0] instanceof iaik.pkcs.pkcs11.objects.Key) {
                            iaik.pkcs.pkcs11.objects.Key keyObject = (iaik.pkcs.pkcs11.objects.Key) tempObjects[0];
                            if (equalsAlias(keyObject, alias)) {
                                foundKey = keyObject;
                                break;
                            }
                        }
                    }
                } while(tempObjects.length > 0);
            } finally {
                session.findObjectsFinal();
            }
            if(foundKey == null)
                return null;

            if(foundKey instanceof iaik.pkcs.pkcs11.objects.SecretKey) {
                return new WrappedSecretKey((iaik.pkcs.pkcs11.objects.SecretKey)foundKey);
            }else if(foundKey instanceof iaik.pkcs.pkcs11.objects.RSAPrivateKey) {
                return new WrappedRSAPrivateKey((iaik.pkcs.pkcs11.objects.RSAPrivateKey)foundKey);
            }else if(foundKey instanceof iaik.pkcs.pkcs11.objects.RSAPublicKey) {
                return new WrappedRSAPublicKey((iaik.pkcs.pkcs11.objects.RSAPublicKey)foundKey);
            }else if(foundKey instanceof iaik.pkcs.pkcs11.objects.ECPrivateKey) {
                return new WrappedECPrivateKey((iaik.pkcs.pkcs11.objects.ECPrivateKey)foundKey);
            }else if(foundKey instanceof iaik.pkcs.pkcs11.objects.ECPublicKey) {
                return new WrappedECPublicKey((iaik.pkcs.pkcs11.objects.ECPublicKey)foundKey);
            }else{
                throw new NoSuchAlgorithmException("Not supported key: " + Long.toString(foundKey.getKeyType().getLongValue(), 16));
            }
        } catch (TokenException e) {
            throw new UnrecoverableKeyException(e.getMessage());
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Provider systemProvider = SingletoneBouncyCastle.getInstance();
        Map<Principal, X509Certificate> certificateMap = new HashMap<>();
        Session session = this.provider.getSession();
        try {
            session.findObjectsInit(new iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate());
            PKCS11Object[] tempObjects;
            List<X509Certificate> certificateChain = new ArrayList<>();
            WrappedX509Certificate foundCert = null;
            try {
                do {
                    tempObjects = session.findObjects(1);
                    if (tempObjects.length > 0) {
                        iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate certObject = (iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate) tempObjects[0];
                        WrappedX509Certificate wrappedCert = new WrappedX509Certificate(certObject, systemProvider);
                        if(foundCert == null && equalsAlias(certObject, alias)) {
                            foundCert = wrappedCert;
                        }
                        certificateMap.put(wrappedCert.getSubjectDN(), wrappedCert);
                    }
                } while(tempObjects.length > 0);
            } finally {
                session.findObjectsFinal();
            }
            if(foundCert == null)
                return null;

            Principal currentPrincipal = foundCert.getIssuerDN();
            certificateChain.add(foundCert);
            while(currentPrincipal != null) {
                X509Certificate current = certificateMap.get(currentPrincipal);
                certificateChain.add(current);
                currentPrincipal = current.getIssuerDN();
            }

            return (Certificate[]) certificateChain.toArray();
        } catch (TokenException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Session session = this.provider.getSession();
        try {
            session.findObjectsInit(new iaik.pkcs.pkcs11.objects.Certificate());
            PKCS11Object[] tempObjects;
            iaik.pkcs.pkcs11.objects.Certificate foundCert = null;
            try {
                do {
                    tempObjects = session.findObjects(1);
                    if (tempObjects.length > 0) {
                        iaik.pkcs.pkcs11.objects.Certificate certObject = (iaik.pkcs.pkcs11.objects.Certificate) tempObjects[0];
                        if(equalsAlias(certObject, alias)) {
                            foundCert = certObject;
                            break;
                        }
                    }
                } while(tempObjects.length > 0);
            } finally {
                session.findObjectsFinal();
            }
            if(foundCert == null)
                return null;

            if(foundCert instanceof iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate) {
                return new WrappedX509Certificate((iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate)foundCert, SingletoneBouncyCastle.getInstance());
            }else{
                throw new NoSuchAlgorithmException("Not supported key: " + Long.toString(foundCert.getCertificateType().getLongValue(), 16));
            }
        } catch (TokenException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("Not implemented yet");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("Not implemented yet");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("Not implemented yet");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new KeyStoreException("Not implemented yet");
    }

    @Override
    public Enumeration<String> engineAliases() {
        Session session = this.provider.getSession();
        try {
            session.findObjectsInit(new iaik.pkcs.pkcs11.objects.Storage());
            PKCS11Object[] tempObjects;
            List<String> labels = new ArrayList<>();
            try {
                do {
                    tempObjects = session.findObjects(1);
                    if (tempObjects.length > 0) {
                        if(this.useAliasId) {
                            Attribute attributes = tempObjects[0].getAttribute(PKCS11Constants.CKA_ID);
                            if (attributes instanceof ByteArrayAttribute && attributes.isPresent()) {
                                if(((ByteArrayAttribute) attributes).getByteArrayValue() != null) {
                                    String id = HexUtils.bytesToHex(((ByteArrayAttribute) attributes).getByteArrayValue());
                                    labels.add(id);
                                }
                            }
                        }else {
                            Attribute attributes = tempObjects[0].getAttribute(PKCS11Constants.CKA_LABEL);
                            if (attributes instanceof CharArrayAttribute && attributes.isPresent()) {
                                if(((CharArrayAttribute) attributes).getCharArrayValue() != null) {
                                    String label = new String(((CharArrayAttribute) attributes).getCharArrayValue());
                                    labels.add(label);
                                }
                            }
                        }
                    }
                } while(tempObjects.length > 0);
            } finally {
                session.findObjectsFinal();
            }

            return Collections.enumeration(labels);
        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return false;
    }

    @Override
    public int engineSize() {
        return 0;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        try {
            return this.engineGetKey(alias, null) != null;
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException e) {
            return false;
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return engineGetCertificate(alias) != null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        Provider systemProvider = SingletoneBouncyCastle.getInstance();
        Session session = this.provider.getSession();
        try {
            session.findObjectsInit(new iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate());
            PKCS11Object[] tempObjects;
            try {
                do {
                    tempObjects = session.findObjects(1);
                    if (tempObjects.length > 0) {
                        iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate certObject = (iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate) tempObjects[0];
                        WrappedX509Certificate wrappedCert = new WrappedX509Certificate(certObject, systemProvider);
                        if(cert.getPublicKey().equals(wrappedCert.getPublicKey())) {
                            return toAlias(certObject);
                        }
                    }
                } while(tempObjects.length > 0);
            } finally {
                session.findObjectsFinal();
            }
        } catch (TokenException | CertificateException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            if(password != null) {
                this.provider.getSession().login(Session.UserType.USER, password);
            }
        } catch (TokenException e) {
            throw new IOException(e);
        }
    }
}

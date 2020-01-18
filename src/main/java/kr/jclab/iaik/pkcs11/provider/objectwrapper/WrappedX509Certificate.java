package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Set;

public class WrappedX509Certificate extends X509Certificate {
    private final X509PublicKeyCertificate p11Certificate;
    private final X509Certificate jcaCertificate;

    public WrappedX509Certificate(iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate p11Certificate, Provider provider) throws CertificateException {
        this.p11Certificate = p11Certificate;

        CertificateFactory certificateFactory;
        if(provider == null) {
            certificateFactory = CertificateFactory.getInstance(this.getType());
        }else{
            certificateFactory = CertificateFactory.getInstance(this.getType(), provider);
        }
        this.jcaCertificate = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(p11Certificate.getValue().getByteArrayValue()));
    }

    public WrappedX509Certificate(iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate p11Certificate) throws CertificateException {
        this(p11Certificate, null);
    }

    public X509PublicKeyCertificate getP11Certificate() {
        return this.p11Certificate;
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return this.jcaCertificate.getEncoded();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        this.jcaCertificate.verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        this.jcaCertificate.verify(key, sigProvider);
    }

    @Override
    public String toString() {
        return this.jcaCertificate.toString();
    }

    @Override
    public PublicKey getPublicKey() {
        return this.jcaCertificate.getPublicKey();
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        this.jcaCertificate.checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        this.jcaCertificate.checkValidity(date);
    }

    @Override
    public int getVersion() {
        return this.jcaCertificate.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return this.jcaCertificate.getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        return this.jcaCertificate.getIssuerDN();
    }

    @Override
    public Principal getSubjectDN() {
        return this.jcaCertificate.getSubjectDN();
    }

    @Override
    public Date getNotBefore() {
        return this.jcaCertificate.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return this.jcaCertificate.getNotAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return this.jcaCertificate.getTBSCertificate();
    }

    @Override
    public byte[] getSignature() {
        return this.jcaCertificate.getSignature();
    }

    @Override
    public String getSigAlgName() {
        return this.jcaCertificate.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return this.jcaCertificate.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return this.jcaCertificate.getSigAlgParams();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return this.jcaCertificate.getIssuerUniqueID();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return this.jcaCertificate.getSubjectUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return this.jcaCertificate.getKeyUsage();
    }

    @Override
    public int getBasicConstraints() {
        return this.jcaCertificate.getBasicConstraints();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return this.jcaCertificate.hasUnsupportedCriticalExtension();
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return this.jcaCertificate.getCriticalExtensionOIDs();
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return this.jcaCertificate.getNonCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return this.jcaCertificate.getExtensionValue(oid);
    }
}

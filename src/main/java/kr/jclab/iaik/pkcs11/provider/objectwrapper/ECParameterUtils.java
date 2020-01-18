package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.io.StringReader;
import java.util.Base64;

public class ECParameterUtils {
    public static X9ECParameters decodeParameterSpec(byte[] encoded) {
        StringBuilder sbPem = new StringBuilder();
        sbPem.append("-----BEGIN EC PARAMETERS-----\n");
        sbPem.append(Base64.getEncoder().encodeToString(encoded));
        sbPem.append("\n-----END EC PARAMETERS-----\n");
        PEMParser pemParser = new PEMParser(new StringReader(sbPem.toString()));
        try {
            Object paramObj = pemParser.readObject();
            X9ECParameters x9Params;
            if(paramObj instanceof ASN1ObjectIdentifier) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)paramObj;
                x9Params = ECNamedCurveTable.getByOID(oid);
            }else if(paramObj instanceof X9ECParameters){
                x9Params = (X9ECParameters)paramObj;
            }else{
                throw new RuntimeException("Wrong parameter: " + paramObj);
            }
            return x9Params;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

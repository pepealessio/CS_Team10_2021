package it.unisa.diem.cs.gruppo10;

import org.apache.commons.lang3.SerializationUtils;

import java.io.Serializable;
import java.security.*;
import java.time.LocalDate;

public class HAToken implements Serializable {
    public final PublicKey pkfu;
    public final LocalDate date;
    byte[] haSign;

    public final PublicKey haPK;

    public HAToken(PublicKey pkfu, LocalDate date, KeyPair haK) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        this.pkfu = pkfu;
        this.date = date;
        haPK = haK.getPublic();
        signToken(haK.getPrivate());
    }

    public boolean verifyToken() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] pkfuByte = pkfu.getEncoded();
        byte[] dateByte = SerializationUtils.serialize(date);

        byte[] tokenToVerify = new byte[pkfuByte.length + dateByte.length];
        System.arraycopy(pkfuByte, 0, tokenToVerify, 0, pkfuByte.length);
        System.arraycopy(dateByte, 0, tokenToVerify, pkfuByte.length, dateByte.length);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(haPK);
        signature.update(tokenToVerify);

        return signature.verify(haSign);
    }

    private void signToken(PrivateKey haSK) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] pkfuByte = pkfu.getEncoded();
        byte[] dateByte = SerializationUtils.serialize(date);

        byte[] tokenToSign = new byte[pkfuByte.length + dateByte.length];
        System.arraycopy(pkfuByte, 0, tokenToSign, 0, pkfuByte.length);
        System.arraycopy(dateByte, 0, tokenToSign, pkfuByte.length, dateByte.length);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(haSK, new SecureRandom());
        signature.update(tokenToSign);

        haSign = signature.sign();
    }
}
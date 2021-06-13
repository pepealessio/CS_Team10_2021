package it.unisa.diem.cs.gruppo10;

import org.apache.commons.lang3.SerializationUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.Serializable;
import java.security.*;
import java.time.Duration;
import java.time.LocalDateTime;

public class ContactMessage implements Serializable {
    public PublicKey pkfu1;
    public LocalDateTime tsNow;
    public byte[] sigBytes;

    public ContactMessage(KeyPair kfu1, byte[] id2Byte) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        this.pkfu1 = kfu1.getPublic();
        this.tsNow = LocalDateTime.now();
        madeSignature(kfu1.getPrivate(), id2Byte);
    }

    /**
     *
     * @param skfu1     secret key of the first user.
     * @param id2Byte   is used because we assume we are making a BT pairing with the device with a certain ID2;
     */
    private void madeSignature(PrivateKey skfu1, byte[] id2Byte) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // We form the array with the message link the equation (2.4)
        byte[] pkfu1Byte = pkfu1.getEncoded();
        byte[] tsNowByte = SerializationUtils.serialize(tsNow);

        byte[] messageToSignByte = new byte[pkfu1Byte.length + tsNowByte.length + id2Byte.length];
        System.arraycopy(pkfu1Byte, 0, messageToSignByte, 0, pkfu1Byte.length);
        System.arraycopy(tsNowByte, 0, messageToSignByte, pkfu1Byte.length, tsNowByte.length);
        System.arraycopy(id2Byte, 0, messageToSignByte, pkfu1Byte.length + tsNowByte.length, id2Byte.length);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        // initialize signature for sign with private key K.getPrivate() and a secure random source
        // The signature algorithms follow the Hash+Sign paradigm, that is a message is first possibly hashed using a CRHF and then is signed
        signature.initSign(skfu1, new SecureRandom());
        signature.update(messageToSignByte);

        sigBytes = signature.sign();
    }

    public boolean verify(byte[] id2Byte) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Verify signature
        byte[] pkfu1Byte = pkfu1.getEncoded();
        byte[] tsNowByte = SerializationUtils.serialize(tsNow);

        byte[] messageToVerifyByte = new byte[pkfu1Byte.length + tsNowByte.length + id2Byte.length];
        System.arraycopy(pkfu1Byte, 0, messageToVerifyByte, 0, pkfu1Byte.length);
        System.arraycopy(tsNowByte, 0, messageToVerifyByte, pkfu1Byte.length, tsNowByte.length);
        System.arraycopy(id2Byte, 0, messageToVerifyByte, pkfu1Byte.length + tsNowByte.length, id2Byte.length);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(pkfu1);
        signature.update(messageToVerifyByte);

        return signature.verify(sigBytes);
    }

    public boolean verifyBTPair(byte[] id2Byte) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // verify Timestamp
        long seconds = Duration.between(LocalDateTime.now(), tsNow).toSeconds();
        if (seconds > 30){
            return false;
        }
        return verify(id2Byte);
    }
}

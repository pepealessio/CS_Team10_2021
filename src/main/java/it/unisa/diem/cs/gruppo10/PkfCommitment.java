package it.unisa.diem.cs.gruppo10;

import org.apache.commons.lang3.SerializationUtils;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.LocalDate;
import java.util.Arrays;

public class PkfCommitment implements Serializable {
    public final byte[] r;
    public final PublicKey pku;
    public final PublicKey pkf;
    public final LocalDate date;
    public byte[] c;

    public PkfCommitment(byte[] r, PublicKey pku, PublicKey pkf, LocalDate date) throws NoSuchAlgorithmException {
        this.r = r;
        this.pku = pku;
        this.pkf = pkf;
        this.date = date;

        generateCommitment();
    }

    public static boolean openCommit(byte[] r, PublicKey pku, PublicKey pkf, LocalDate date, byte[] c) throws NoSuchAlgorithmException {
        byte[] pkuByte = pku.getEncoded();
        byte[] pkfByte = pkf.getEncoded();
        byte[] dateByte = SerializationUtils.serialize(date);

        byte[] toOpen = new byte[r.length + pkuByte.length + pkfByte.length + dateByte.length];
        System.arraycopy(r, 0, toOpen, 0, r.length);
        System.arraycopy(pkuByte, 0, toOpen, r.length, pkuByte.length);
        System.arraycopy(pkfByte, 0, toOpen, r.length + pkuByte.length, pkfByte.length);
        System.arraycopy(dateByte, 0, toOpen, r.length + pkuByte.length + pkfByte.length, dateByte.length);

        MessageDigest h = MessageDigest.getInstance("SHA256");
        h.update(toOpen);
        return true;
        // return Arrays.equals(h.digest(), c);
    }

    public byte[] getCommitment() {
        return c;
    }

    private void generateCommitment() throws NoSuchAlgorithmException {
        byte[] pkuByte = pku.getEncoded();
        byte[] pkfByte = pkf.getEncoded();
        byte[] dateByte = SerializationUtils.serialize(date);

        byte[] toCommit = new byte[r.length + pkuByte.length + pkfByte.length + dateByte.length];
        System.arraycopy(r, 0, toCommit, 0, r.length);
        System.arraycopy(pkuByte, 0, toCommit, r.length, pkuByte.length);
        System.arraycopy(pkfByte, 0, toCommit, r.length + pkuByte.length, pkfByte.length);
        System.arraycopy(dateByte, 0, toCommit, r.length + pkuByte.length + pkfByte.length, dateByte.length);

        MessageDigest h = MessageDigest.getInstance("SHA256");
        h.update(toCommit);
        c = h.digest();
    }
}
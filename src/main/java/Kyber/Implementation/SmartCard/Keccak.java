package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.CryptoException;
import Kyber.Implementation.SmartCard.dummy.Util;
import Kyber.Implementation.SmartCard.dummy.JCSystem;

public class Keccak {

    //Defines
    public static final short   KECCAKF_ROUNDS      = (short)  24;
    public static final short   WORDL               = (short)   8;
    public static final short   STATE_BYTES         = (short) 200;
    public static final short   STATE_SLICE         = (short)  25;
    public final static byte    ALG_SHA3_256        = (byte)    8;
    public final static byte    ALG_SHA3_512        = (byte)   10;
    public final static byte    ALG_SHAKE_128       = (byte)   15;
    public final static byte    ALG_SHAKE_256       = (byte)   16;

    //* this stuff is in big endian!
    final static byte[] KECCAKF_RNDC = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, // 0x0000000000000001
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x82, // 0x0000000000008082
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x8a, // 0x800000000000808a
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x00, // 0x8000000080008000
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x8b, // 0x000000000000808b
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x01, // 0x0000000080000001
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x81, // 0x8000000080008081
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x09, // 0x8000000000008009
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x8a, // 0x000000000000008a
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x88, // 0x0000000000000088
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x09, // 0x0000000080008009
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x0a, // 0x000000008000000a
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x8b, // 0x000000008000808b
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x8b, // 0x800000000000008b
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x89, // 0x8000000000008089
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x03, // 0x8000000000008003
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x02, // 0x8000000000008002
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, // 0x8000000000000080
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x0a, // 0x000000000000800a
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x0a, // 0x800000008000000a
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x81, // 0x8000000080008081
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x80, // 0x8000000000008080
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x01, // 0x0000000080000001
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x08};// 0x8000000080008008

    final static byte[] KECCAKF_ROTC = {
            (byte) 0x01, (byte) 0x03, (byte) 0x06, (byte) 0x0a, (byte) 0x0f, (byte) 0x15, (byte) 0x1c, (byte) 0x24,
            (byte) 0x2d, (byte) 0x37, (byte) 0x02, (byte) 0x0e, (byte) 0x1b, (byte) 0x29, (byte) 0x38, (byte) 0x08,
            (byte) 0x19, (byte) 0x2b, (byte) 0x3e, (byte) 0x12, (byte) 0x27, (byte) 0x3d, (byte) 0x14, (byte) 0x2c};

    final static byte[] KECCAKF_PILN = {
            (byte) 0x0a, (byte) 0x07, (byte) 0x0b, (byte) 0x11, (byte) 0x12, (byte) 0x03, (byte) 0x05, (byte) 0x10,
            (byte) 0x08, (byte) 0x15, (byte) 0x18, (byte) 0x04, (byte) 0x0f, (byte) 0x17, (byte) 0x13, (byte) 0x0d,
            (byte) 0x0c, (byte) 0x02, (byte) 0x14, (byte) 0x0e, (byte) 0x16, (byte) 0x09, (byte) 0x06, (byte) 0x01};

    final static byte[] ROTL_MASK = {
            (byte) 0x00, (byte) 0x01, (byte) 0x03, (byte) 0x07, (byte) 0x0F, (byte) 0x1F, (byte) 0x3F, (byte) 0x7F};

    //Keccak instance
    private static Keccak  m_instance = null;  // instance of cipher itself

    //Keccak context
    private static short  mdlen;
    private static short pt;
    private static short rsiz;

    //Pad for NIST-Sha3 = 0x06, Shake = 0x1F
    private static byte pad = 0x06;

    //Arrays
    private final byte[] st   = JCSystem.makeTransientByteArray(STATE_BYTES,       JCSystem.CLEAR_ON_DESELECT); // state
    private final byte[] bc   = JCSystem.makeTransientByteArray((short) (WORDL*5), JCSystem.CLEAR_ON_DESELECT); // C
    private final byte[] t    = JCSystem.makeTransientByteArray(WORDL,             JCSystem.CLEAR_ON_DESELECT); // auxiliary temp
    private final byte[] rotl = JCSystem.makeTransientByteArray((short) (WORDL+1), JCSystem.CLEAR_ON_DESELECT); // rotl result

    //swap endianness on state
    void swapEndian(byte[] arr) {
        short i;
        byte aux;
        for (i = 0; i < STATE_SLICE; i++) {
            aux = arr[(short) (i*WORDL)];
            arr[(short)( i*WORDL)] = arr[(short) (i*WORDL+7)];
            arr[(short) (i*WORDL+7)] = aux;
            aux = arr[(short) (i*WORDL+1)];
            arr[(short) (i*WORDL+1)] = arr[(short) (i*WORDL+6)];
            arr[(short) (i*WORDL+6)] = aux;
            aux = arr[(short) (i*WORDL+2)];
            arr[(short) (i*WORDL+2)] = arr[(short) (i*WORDL+5)];
            arr[(short) (i*WORDL+5)] = aux;
            aux = arr[(short) (i*WORDL+3)];
            arr[(short) (i*WORDL+3)] = arr[(short) (i*WORDL+4)];
            arr[(short) (i*WORDL+4)] = aux;
        }
    }

    //word bit rotation of to the left
    //arr has to be array of 8 bytes, result stored in out, arr is not modified
    //EXACT index
    void rotlW(byte[] arr, short startIndex, short shift) {

        //copy input to output, shifted by whole bytes
        Util.arrayCopyNonAtomic(arr, (short) (startIndex + (shift/8)), rotl, (short) 0, (short) (WORDL-(shift/8)));
        Util.arrayCopyNonAtomic(arr, startIndex, rotl, (short) (WORDL-(shift/8)), (short) (shift/8));
        shift %= 8; //now shift only up to 8 bits

        //generate masks
        byte comp = (byte) (8 - shift);

        //rotate using masks
        if (shift > 0) {
            rotl[8] = (byte)(rotl[0]);
            rotl[0] = (byte)((byte)(rotl[0] << shift) | (byte)((rotl[1] >> comp) & ROTL_MASK[shift]));
            rotl[1] = (byte)((byte)(rotl[1] << shift) | (byte)((rotl[2] >> comp) & ROTL_MASK[shift]));
            rotl[2] = (byte)((byte)(rotl[2] << shift) | (byte)((rotl[3] >> comp) & ROTL_MASK[shift]));
            rotl[3] = (byte)((byte)(rotl[3] << shift) | (byte)((rotl[4] >> comp) & ROTL_MASK[shift]));
            rotl[4] = (byte)((byte)(rotl[4] << shift) | (byte)((rotl[5] >> comp) & ROTL_MASK[shift]));
            rotl[5] = (byte)((byte)(rotl[5] << shift) | (byte)((rotl[6] >> comp) & ROTL_MASK[shift]));
            rotl[6] = (byte)((byte)(rotl[6] << shift) | (byte)((rotl[7] >> comp) & ROTL_MASK[shift]));
            rotl[7] = (byte)((byte)(rotl[7] << shift) | (byte)((rotl[8] >> comp) & ROTL_MASK[shift]));
        }
    }

    //bitwise XOR of two words, save in w1
    //REQUIRES EXACT INDEX
    void xorWords(byte[] w1, short index1, byte[] w2, short index2) {
        short i;
        for (i = 0; i < WORDL; i++)
            w1[(short)(index1+i)] ^= w2[(short)(index2+i)];
    }

    //bitwise AND of two words, save in w1
    //REQUIRES EXACT INDEX
    void andWords(byte[] w1, short index1, byte[] w2, short index2) {
        short i;
        for (i = 0; i < WORDL; i++)
            w1[(short) (index1+i)] &= w2[(short) (index2+i)];
    }

    //Negate a word w2, save it into w1
    //REQUIRES EXACT INDEX
    void negateWord(byte[] w1, short index1, byte[] w2, short index2) {
        short i;
        for (i = 0; i < WORDL; i++)
            w1[(short) (index1+i)] = (byte) ~w2[(short) (index2+i)];
    }

    //KECCAK FUNCTION - updating state with 24 rounds
    void keccakf(byte[] st) {
        //byte[WORDL] is the same as uint64_t

        short i, r;      //iterators

        //change endianness
        swapEndian(st);

        for (r = 0; r < KECCAKF_ROUNDS; r++) {

            // Theta function (NIST.FIPS.202 page 20), sha3tiny.c line 50
            // Successive XORing into state, then assigning into C
            Util.arrayCopyNonAtomic(st, (short)  0, bc, (short)  0, WORDL);
            xorWords(bc, (short)  0, st, (short)  40);
            xorWords(bc, (short)  0, st, (short)  80);
            xorWords(bc, (short)  0, st, (short) 120);
            xorWords(bc, (short)  0, st, (short) 160);
            Util.arrayCopyNonAtomic(st, (short)  8, bc, (short)  8, WORDL);
            xorWords(bc, (short)  8, st, (short)  48);
            xorWords(bc, (short)  8, st, (short)  88);
            xorWords(bc, (short)  8, st, (short) 128);
            xorWords(bc, (short)  8, st, (short) 168);
            Util.arrayCopyNonAtomic(st, (short) 16, bc, (short) 16, WORDL);
            xorWords(bc, (short) 16, st, (short)  56);
            xorWords(bc, (short) 16, st, (short)  96);
            xorWords(bc, (short) 16, st, (short) 136);
            xorWords(bc, (short) 16, st, (short) 176);
            Util.arrayCopyNonAtomic(st, (short) 24, bc, (short) 24, WORDL);
            xorWords(bc, (short) 24, st, (short)  64);
            xorWords(bc, (short) 24, st, (short) 104);
            xorWords(bc, (short) 24, st, (short) 144);
            xorWords(bc, (short) 24, st, (short) 184);
            Util.arrayCopyNonAtomic(st, (short) 32, bc, (short) 32, WORDL);
            xorWords(bc, (short) 32, st, (short)  72);
            xorWords(bc, (short) 32, st, (short) 112);
            xorWords(bc, (short) 32, st, (short) 152);
            xorWords(bc, (short) 32, st, (short) 192);

            //sha3tiny.c line 55
            rotlW(bc, (short) 8, (short) 1);
            xorWords(rotl, (short) 0, bc, (short) 32);
            Util.arrayCopyNonAtomic(rotl, (short) 0, t, (short) 0, WORDL);
            xorWords(st, (short)   0, t, (short) 0);
            xorWords(st, (short)  40, t, (short) 0);
            xorWords(st, (short)  80, t, (short) 0);
            xorWords(st, (short) 120, t, (short) 0);
            xorWords(st, (short) 160, t, (short) 0);
            rotlW(bc, (short) 16, (short) 1);
            xorWords(rotl, (short) 0, bc, (short) 0);
            Util.arrayCopyNonAtomic(rotl, (short) 0, t, (short) 0, WORDL);
            xorWords(st, (short)   8, t, (short) 0);
            xorWords(st, (short)  48, t, (short) 0);
            xorWords(st, (short)  88, t, (short) 0);
            xorWords(st, (short) 128, t, (short) 0);
            xorWords(st, (short) 168, t, (short) 0);
            rotlW(bc, (short) 24, (short) 1);
            xorWords(rotl, (short) 0, bc, (short) 8);
            Util.arrayCopyNonAtomic(rotl, (short) 0, t, (short) 0, WORDL);
            xorWords(st, (short)  16, t, (short) 0);
            xorWords(st, (short)  56, t, (short) 0);
            xorWords(st, (short)  96, t, (short) 0);
            xorWords(st, (short) 136, t, (short) 0);
            xorWords(st, (short) 176, t, (short) 0);
            rotlW(bc, (short) 32, (short) 1);
            xorWords(rotl, (short) 0, bc, (short) 16);
            Util.arrayCopyNonAtomic(rotl, (short) 0, t, (short) 0, WORDL);
            xorWords(st, (short)  24, t, (short) 0);
            xorWords(st, (short)  64, t, (short) 0);
            xorWords(st, (short) 104, t, (short) 0);
            xorWords(st, (short) 144, t, (short) 0);
            xorWords(st, (short) 184, t, (short) 0);
            rotlW(bc, (short) 0, (short) 1);
            xorWords(rotl, (short) 0, bc, (short) 24);
            Util.arrayCopyNonAtomic(rotl, (short) 0, t, (short) 0, WORDL);
            xorWords(st, (short)  32, t, (short) 0);
            xorWords(st, (short)  72, t, (short) 0);
            xorWords(st, (short) 112, t, (short) 0);
            xorWords(st, (short) 152, t, (short) 0);
            xorWords(st, (short) 192, t, (short) 0);

            //Rho and Pi functions together (NIST.FIPS.202 page 20-22), sha3tiny line 60
            Util.arrayCopyNonAtomic(st, WORDL, t, (short) 0, WORDL);
            for (i = 0; i < 24; i++) {
                Util.arrayCopyNonAtomic(st, (short) (KECCAKF_PILN[i] * WORDL), bc, (short) 0, WORDL);
                rotlW(t, (short) 0, KECCAKF_ROTC[i]);
                Util.arrayCopyNonAtomic(rotl, (short) 0, st, (short) (KECCAKF_PILN[i] * WORDL), WORDL);
                Util.arrayCopyNonAtomic(bc,   (short) 0,  t, (short) 0,                         WORDL);
            }

            //Chi function (NIST.FIPS.202 page 23), sha3tiny line 69
            Util.arrayCopyNonAtomic(st, (short)  0, bc, (short)  0, WORDL);
            Util.arrayCopyNonAtomic(st, (short)  8, bc, (short)  8, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 16, bc, (short) 16, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 24, bc, (short) 24, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 32, bc, (short) 32, WORDL);
            negateWord(t, (short) 0, bc, (short)  8); andWords(t, (short) 0, bc, (short) 16); xorWords(st, (short)  0, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 16); andWords(t, (short) 0, bc, (short) 24); xorWords(st, (short)  8, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 24); andWords(t, (short) 0, bc, (short) 32); xorWords(st, (short) 16, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 32); andWords(t, (short) 0, bc, (short)  0); xorWords(st, (short) 24, t, (short) 0);
            negateWord(t, (short) 0, bc, (short)  0); andWords(t, (short) 0, bc, (short)  8); xorWords(st, (short) 32, t, (short) 0);
            Util.arrayCopyNonAtomic(st, (short) 40, bc, (short)  0, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 48, bc, (short)  8, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 56, bc, (short) 16, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 64, bc, (short) 24, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 72, bc, (short) 32, WORDL);
            negateWord(t, (short) 0, bc, (short)  8); andWords(t, (short) 0, bc, (short) 16); xorWords(st, (short) 40, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 16); andWords(t, (short) 0, bc, (short) 24); xorWords(st, (short) 48, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 24); andWords(t, (short) 0, bc, (short) 32); xorWords(st, (short) 56, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 32); andWords(t, (short) 0, bc, (short)  0); xorWords(st, (short) 64, t, (short) 0);
            negateWord(t, (short) 0, bc, (short)  0); andWords(t, (short) 0, bc, (short)  8); xorWords(st, (short) 72, t, (short) 0);
            Util.arrayCopyNonAtomic(st, (short)  80, bc, (short)  0, WORDL);
            Util.arrayCopyNonAtomic(st, (short)  88, bc, (short)  8, WORDL);
            Util.arrayCopyNonAtomic(st, (short)  96, bc, (short) 16, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 104, bc, (short) 24, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 112, bc, (short) 32, WORDL);
            negateWord(t, (short) 0, bc, (short)  8); andWords(t, (short) 0, bc, (short) 16); xorWords(st, (short)  80, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 16); andWords(t, (short) 0, bc, (short) 24); xorWords(st, (short)  88, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 24); andWords(t, (short) 0, bc, (short) 32); xorWords(st, (short)  96, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 32); andWords(t, (short) 0, bc, (short)  0); xorWords(st, (short) 104, t, (short) 0);
            negateWord(t, (short) 0, bc, (short)  0); andWords(t, (short) 0, bc, (short)  8); xorWords(st, (short) 112, t, (short) 0);
            Util.arrayCopyNonAtomic(st, (short) 120, bc, (short)  0, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 128, bc, (short)  8, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 136, bc, (short) 16, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 144, bc, (short) 24, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 152, bc, (short) 32, WORDL);
            negateWord(t, (short) 0, bc, (short)  8); andWords(t, (short) 0, bc, (short) 16); xorWords(st, (short) 120, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 16); andWords(t, (short) 0, bc, (short) 24); xorWords(st, (short) 128, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 24); andWords(t, (short) 0, bc, (short) 32); xorWords(st, (short) 136, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 32); andWords(t, (short) 0, bc, (short)  0); xorWords(st, (short) 144, t, (short) 0);
            negateWord(t, (short) 0, bc, (short)  0); andWords(t, (short) 0, bc, (short)  8); xorWords(st, (short) 152, t, (short) 0);
            Util.arrayCopyNonAtomic(st, (short) 160, bc, (short)  0, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 168, bc, (short)  8, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 176, bc, (short) 16, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 184, bc, (short) 24, WORDL);
            Util.arrayCopyNonAtomic(st, (short) 192, bc, (short) 32, WORDL);
            negateWord(t, (short) 0, bc, (short)  8); andWords(t, (short) 0, bc, (short) 16); xorWords(st, (short) 160, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 16); andWords(t, (short) 0, bc, (short) 24); xorWords(st, (short) 168, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 24); andWords(t, (short) 0, bc, (short) 32); xorWords(st, (short) 176, t, (short) 0);
            negateWord(t, (short) 0, bc, (short) 32); andWords(t, (short) 0, bc, (short)  0); xorWords(st, (short) 184, t, (short) 0);
            negateWord(t, (short) 0, bc, (short)  0); andWords(t, (short) 0, bc, (short)  8); xorWords(st, (short) 192, t, (short) 0);

            //Iota function (NIST.FIPS.202 page 23), sha3tiny line 77
            xorWords(st, (short) 0, KECCAKF_RNDC, (short) (r * WORDL));
        }

        //swap endianness
        swapEndian(st);
    }

    // BEGIN INTERFACE //

    //Constructor
    protected Keccak() {}

    //generate hash of all data, reset engine
    public short doFinal(byte[] inBuff, byte[] outBuff) throws CryptoException {
        this.reset();
        short i;
        short inOffset = 0;
        short outOffset = 0;
        short inLength = (short)inBuff.length;
        update(inBuff, inOffset, inLength);

        st[pt] ^= pad;
        st[(short) (rsiz-1)] ^= 0x80;

        short chunks = (short)(mdlen/rsiz);
        short last = (short)(mdlen%rsiz);
        short copiedBytes = 0;

        while (chunks > 0)
        {
            keccakf(st);
            chunks--;
            for (i = 0; i < rsiz; i++)
            {
                outBuff[(short)(copiedBytes + outOffset + i)] = st[i];
            }
            copiedBytes+=rsiz;
        }
        if (last > 0)
        {
            keccakf(st);
            for (i = 0; i < last; i++)
            {
                outBuff[(short)(copiedBytes + outOffset + i)] = st[i];
            }
        }
        return mdlen;
    }

    // Set shake return length
    public void setShakeDigestLength(short length)
    {
        mdlen = length;
    }

    // get Keccak instance
    public static Keccak getInstance(byte algorithm) throws CryptoException {
        switch (algorithm) {
            case ALG_SHA3_256:
                pad = 0x06;
                mdlen = (short) 32;
                rsiz = (short) 136;
                break;
            case ALG_SHA3_512:
                pad = 0x06;
                mdlen = (short) 64;
                rsiz = (short)  72;
                break;
            case ALG_SHAKE_128:
                pad = 0x1F;
                mdlen = (short) 32;
                rsiz = (short) 168;
                break;
            case ALG_SHAKE_256:
                pad = 0x1F;
                mdlen = (short) 64;
                rsiz = (short) 136;
                break;
            default:
                throw new CryptoException(CryptoException.NO_SUCH_ALGORITHM);
        }
        pt = 0;

        if (m_instance == null) {
            m_instance = new Keccak();
        }
        return m_instance;
    }

    public void reset() {
        //clear arrays and partitioning tracker
        Util.arrayFillNonAtomic(st,   (short) 0, STATE_BYTES,         (byte) 0);
        Util.arrayFillNonAtomic(bc,   (short) 0, (short) (5 * WORDL), (byte) 0);
        Util.arrayFillNonAtomic(t,    (short) 0, WORDL,               (byte) 0);
        Util.arrayFillNonAtomic(rotl, (short) 0, (short) (WORDL + 1), (byte) 0);
        pt = 0;
    }

    //add more data into hash
    //input buffer, offset in buffer, byte length of message
    public void update(byte[] inBuff, short inOffset, short inLength) {
        short j = pt;
        short i;
        for (i = 0; i < inLength; i++) {
            //this is big endian
            st[j++] ^= inBuff[(short) (inOffset + i)];
            if (j >= rsiz) {
                keccakf(st);
                j = 0;
            }
        }
        pt = j;
    }
}
package com.card.cardpet;

import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Signature;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;
import javacardx.apdu.ExtendedLength;

public class CardPet extends Applet implements ExtendedLength
{
    private static final byte INS_VERIFY=(byte)0x00;
    private static final byte INS_CREATE=(byte)0x01;
    private static final byte INS_GET=(byte)0x02;
    private static final byte INS_UPDATE=(byte)0x03;
    
    private static final byte PIN=(byte)0x04;
    private static final byte PETCARD=(byte)0x05;
    private static final byte SIGNATURE=(byte)0x06;
    
    private static final byte INFORMATION=(byte)0x07;
    private static final byte REMAINING_BALANCE=(byte)0x08;
    private static final byte AVATAR=(byte)0x09;
    
    private static final byte INS_RESET_TRY_PIN=(byte)0x10;
    
    private final PIN pin;
    private final AESKey key;
    private final Signature signature;
    private final byte[]avatarBuf;
    private final byte[] signatureBuf;
    private Card card;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    
    public CardPet(){
    	//khoi tao PIn
	    pin=new PIN();
	    //set key aes loai aes 128 bit ecb
	    key=(AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,(short)128,false);
	                                 //thuat toan tao chu ky mong muon, false : Khong muon chia se giua cac applet
	    signature=Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
	    avatarBuf=new byte[Avatar.MAX_SIZE_AVATAR];
	    //DES Key Length=128
	    signatureBuf=JCSystem.makeTransientByteArray((short)(KeyBuilder.LENGTH_DES3_2KEY),JCSystem.CLEAR_ON_DESELECT);
    }
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new CardPet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_VERIFY:
			verify(apdu);
			break;
		case INS_CREATE:
			create(apdu);
			break;
		case INS_GET:
			get(apdu);
			break;
		case INS_UPDATE:
			update(apdu);
			break;
		case INS_RESET_TRY_PIN:
			resetPin(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	private void create(APDU apdu) throws ISOException{
		byte[] buf=apdu.getBuffer();
		switch(buf[ISO7816.OFFSET_P1]){
		case PETCARD:
			createInformation(apdu);
			break;
		case SIGNATURE:
			createSignature(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	private void get(APDU apdu) throws ISOException{
		if(card==null){
			return;
		}
		byte[] buf=apdu.getBuffer();
		if(buf[ISO7816.OFFSET_P1]!=PETCARD){
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		switch(buf[ISO7816.OFFSET_P2]){
		case INFORMATION:
			getInformation(apdu);
			break;
		case REMAINING_BALANCE:
			getRemainingBalance(apdu);
			break;
		case AVATAR:
			getAvatar(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	private void update(APDU apdu) throws ISOException{
		if(card==null){
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		byte[]buf=apdu.getBuffer();
		switch(buf[ISO7816.OFFSET_P1]){
		case PETCARD:
			break;
		case PIN:
			updatePin(apdu);
			return;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		byte P2=buf[ISO7816.OFFSET_P2];
		if(P2==AVATAR){
			updateAvatar(apdu);
			return;
		}
		if(buf[ISO7816.OFFSET_LC]==(byte)0x00){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		switch(P2){
		case INFORMATION:
			updateInformation(buf);
			break;
		case REMAINING_BALANCE:
			updateRemainingBalance(buf);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	
	//kiem tra ma pin nguoi dung nhap vao
	//tra ve null -> thanh cong, tra ve so lan thu ma pin -> that bai
	private void verify(APDU apdu){
		byte[] buf=apdu.getBuffer();
		byte offset=ISO7816.OFFSET_CDATA;
		short length=buf[ISO7816.OFFSET_LC];
		//thanh cong
		if(pin.match(buf,offset,length)){
			return;
		}
		//tra ve so lan thu ma PIN
		buf[ISO7816.OFFSET_CDATA]=pin.getTryRemaining();
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA,(short)1);
		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	}
	
	 //khoi tao thong tin trong the
     public void createInformation(APDU apdu) throws ISOException{
    	 //thong tin da duoc khoi tao
	     if(card !=null){
		     ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
	     }
	     byte[]buf=apdu.getBuffer();
	     //thong tin app->th = null
	     if(buf[ISO7816.OFFSET_LC]==(byte)0x00){
		     ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	     }
	     byte offset;
	     short length;
	     //ma pin duoc bam va them byte 0 lam key cho AES
	     key.setKey(pin.getPIN(),(short)0);
	     //khoi tao thong tin trong the
	     JCSystem.beginTransaction();
	     card=new Card();
	     //vi du thong tin dua vao co dang:
	     //id=xxxxxx;
	     //namePeople=HienTrang;
	     //namePet = Pi;
	     //the se nhan duoc 6xxxxxx9HienTrang2Pi
	     //doc ky tu dau de lay do dai thuoc tinh
	     // day chi la vi du, con du lieu trong the là dang byte array
	    
	    
	     //id
	     offset=ISO7816.OFFSET_CDATA;
	     length=(short)buf[offset];
	     card.setId(buf,(short)(offset+1),length,key);
	    
	     //name people
	     offset+=(byte)(length+1);
	     length=(short)buf[offset];
	     card.setNamePeople(buf,(short)(offset+1),length,key);
	    
	     // //name pet
	     // offset+=(byte)(length+1);
	     // length=(short)buf[offset];
	     // card.setNamePet(buf,(short)(offset+1),length,key);
	    
	     //date of birth
	     offset+=(byte)(length+1);
	     length=(short)buf[offset];
	     card.setDateOfBirth(buf,(short)(offset+1),length,key);
	    
	     //number phone
	     offset+=(byte)(length+1);
	     length=(short)buf[offset];
	     card.setNumberPhone(buf,(short)(offset+1),length,key);
	    
	     //remainingBalance
	     offset+=(byte)(length+1);
	     length=(short)buf[offset];
	     card.setRemainingBalance(buf,(short)(offset+1),length,key);
	     JCSystem.commitTransaction();
	    
	     //Sau khi khoi tao thong tin, se sinh 1 cap khoa
	     KeyPair keyPair=RSA.generateKeyPair();
	     privateKey=(RSAPrivateKey)keyPair.getPrivate();
	     publicKey=(RSAPublicKey) keyPair.getPublic();
	    
	     length=RSA.serializePublicKey(publicKey,buf,(short)0);
	    //gui public key -> App, App nhan duoc public key => thong bao thanh cong khoi tao thong tin
	     apdu.setOutgoingAndSend((short)0,length);
}
    
    
    //TAO chu ky, ham nay duoc dung khi nguoi dung nhan nut thanh toan, 
    //App gui random code, the ky=private key+ random code, 
    //The phan hoi cho app chu ky vua tao
    private void createSignature(APDU apdu) throws ISOException {
		if (card == null) {	
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		
		byte[] buffer = apdu.getBuffer();
		short length = buffer[ISO7816.OFFSET_LC];
		
		if (length == (byte) 0x00) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		//Cap nhat signature(doi tuong chinh de ky,MODE_SIGN:Bieu dien che do ky)
		signature.init(privateKey, Signature.MODE_SIGN);
		//tao chu ky
		signature.sign(buffer, (short) ISO7816.OFFSET_CDATA, length, signatureBuf, (short) 0);
		//gui chu ky cho the
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) signatureBuf.length);
		apdu.sendBytesLong(signatureBuf, (short) 0, (short) signatureBuf.length);
	}
    
    
    private void getInformation(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte offset;
		//card.getId/getNamePeople....tra ve kich thuoc cua thong tin, the -> app thong tin dang bytes[]
		offset = (byte) 0x00;
		buffer[offset] = (byte) card.getId(key, buffer, (short) (offset + 1));

		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) card.getNamePeople(key, buffer, (short) (offset + 1));

        // offset += (short) (buffer[offset] + 1);
		// buffer[offset] = (byte) card.getNamePet(key, buffer, (short) (offset + 1));
		
		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) card.getDateOfBirth(key, buffer, (short) (offset + 1));


		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) card.getNumberPhone(key, buffer, (short) (offset + 1));

		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) card.getRemainingBalance(key, buffer, (short) (offset + 1));
        
		apdu.setOutgoingAndSend((short) 0, (short) (offset + buffer[offset] + 1));
	}
    
    //tra ve so du
    private void getRemainingBalance(APDU apdu){
	    byte[]buf=apdu.getBuffer();
	    short length=card.getRemainingBalance(key,buf,(short)0);
	    apdu.setOutgoingAndSend((short)0,length);
    }
    private short getMin(short lengthOne,short lengthTwo){
	    if(lengthOne<=lengthTwo){
		    return lengthOne;
	    }
	    return lengthTwo;
    }
    //tra ve image
    private void getAvatar(APDU apdu) {
		short size = card.getAvatar(key, avatarBuf, (short) 0);
		short maxLength = apdu.setOutgoing();
		short length = 0;
		short pointer = 0;
		//bo dem apdu
		apdu.setOutgoingLength(size);
		while (size > 0) {
			length = getMin(size, maxLength);
			apdu.sendBytesLong(avatarBuf, pointer, length);
			size -= length;
			pointer += length;
		}
	}
    private void updatePin(APDU apdu) throws ISOException{
	    byte[]buf=apdu.getBuffer();
	    byte offset=ISO7816.OFFSET_CDATA;
	    short length=(short) buf[offset];
	    //app gui ma pin cu + ma pin moi, the xac thuc ma pin cu
	    if(pin.match(buf,(byte)(offset+1),length)){
	    	//xac thuc thanh cong, app cap nhat ma PIN moi
		    offset+=(byte)(length+1);
		    length=(short)buf[offset];
		    pin.update(buf,(byte)(offset+1),length);
		    return;
	    }
	    //xac thuc that bai, the -> App so lan thu ma PIN
	    buf[ISO7816.OFFSET_CDATA]=pin.getTryRemaining();
	    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA,(short)1);
	    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    private void updateAvatar(APDU apdu){
	    byte[]buf=apdu.getBuffer();
	    short received=apdu.setIncomingAndReceive();
	    short offset=apdu.getOffsetCdata();
	    short pointer=0;
	    //su dung b dem apdu
	    while(received>0){
		    Util.arrayCopyNonAtomic(buf,offset,avatarBuf,pointer,received);
		    pointer+=received;
		    received=apdu.receiveBytes(offset);
	    }
	    card.setAvatar(avatarBuf,(short)0,pointer,key);
    }
    private void updateInformation(byte[]buf){
	    //thong tin chua duoc khoi tao
	    byte offset;
	    short length;
	    JCSystem.beginTransaction();
	    offset=ISO7816.OFFSET_CDATA;
	    //set name people
	    length=(short) buf[offset];
	    card.setNamePeople(buf,(short)(offset+1),length,key);
	    //set name pet
	    // offset+=(byte)(length+1);
	    // length=(short)buf[offset];
	    // card.setNamePet(buf,(short)(offset+1),length,key);
	    //set date of birth pet
	    offset+=(byte)(length+1);
	    length=(short)buf[offset];
	    card.setDateOfBirth(buf,(short)(offset+1),length,key);
	    //set number phone
	    offset+=(byte)(length+1);
	    length=(short)buf[offset];
	    card.setNumberPhone(buf,(short)(offset+1),length,key);
	    JCSystem.commitTransaction();
	    
    }
    private void updateRemainingBalance(byte[]buf){
	    
	    short offset=ISO7816.OFFSET_CDATA;
	    short length=buf[ISO7816.OFFSET_LC];
	    JCSystem.beginTransaction();
	    card.setRemainingBalance(buf,offset,length,key);
	    JCSystem.commitTransaction();
	    
    }
    private void resetPin(APDU apdu){
	    pin.resetRetryPin();
	    return;
    }
    
}

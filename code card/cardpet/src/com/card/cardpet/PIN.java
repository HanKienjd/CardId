package com.card.cardpet;
import javacard.security.MessageDigest;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class PIN {
	private static final byte[]PIN_DEFAULT=new byte[]{(byte)'1',(byte)'1',(byte)'1',(byte)'1',(byte)'1',(byte)'1'};
	private static final byte PIN_RETRY=3;
	private final byte[]pin;
	private byte retry;
	private byte tryRemaining;
	//MessageDigest co so thuat toan de bam
	private final MessageDigest messageDigest;
	public boolean isValidated;
	public PIN(){
		this.pin=new byte[16];
		this.retry=PIN_RETRY;
		this.tryRemaining=PIN_RETRY;
		this.isValidated=false;
		//ALG_MD5: Khoi kich thuoc sduoc su dung la 64
		this.messageDigest=MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
		//bam mã Pin
		messageDigest.doFinal(PIN_DEFAULT, (short) 0, (short) PIN_DEFAULT.length, pin, (short) 0);
	}
	//xac thuc nguoi dung bang ma pin,
	//true -> tra ve null
	//false -> tra ve so lan thu ma pin
	public boolean match(byte[]buf,byte offset,short length){
		if(tryRemaining==(byte)0x00){
			return false;
		
		}
		byte[]temp=JCSystem.makeTransientByteArray((short) pin.length, JCSystem.CLEAR_ON_DESELECT);
		messageDigest.reset();
		//bam ma pin vua nhap vao
		messageDigest.doFinal(buf, (short) offset, length, temp, (short) 0);
		//so sanh ma pin nhap va ma pin hien tai
		if(Util.arrayCompare(pin,(short)0,temp,(short)0,(short)pin.length)==(byte)0x00){
			tryRemaining=retry;
			isValidated=true;
			return true;
		}
		tryRemaining--;
		return false;
	}
	//cap nhat ma pin
	public void update(byte[]buf,byte offset,short length){
		if(length<1){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		//bam ma pin vua cap nhat
		messageDigest.reset();
		messageDigest.doFinal(buf,(short)offset,length,pin,(short)0);
		tryRemaining=retry;
	}
	//reset so lan nhap pin
	public void resetRetryPin(){
		tryRemaining=retry;
		isValidated=false;
	}
	public byte[]getPIN(){
		return pin;
	}
	public byte getTryRemaining(){
		return tryRemaining;
	}
	public boolean isValidated(){
		return isValidated;
	}
}

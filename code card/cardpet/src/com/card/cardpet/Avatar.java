package com.card.cardpet;
import javacard.framework.Util;
import javacard.security.AESKey;

public class Avatar {
	public static final short MAX_SIZE_AVATAR=(short)4096;
	private final byte[] avatar=new byte[MAX_SIZE_AVATAR];
	private short size=0;
	
	public short getAvatar(AES aes,AESKey key,byte[]buf,short offset){
		//giai ma hinh anh
		aes.decrypt(avatar,(short)0,MAX_SIZE_AVATAR,key,buf,offset);
		return size;
	}
	public void setAvatar(byte[]buf,short offset,short length,AES aes,AESKey key){
	//ma hoa hinh anh
		aes.encrypt(buf,offset,MAX_SIZE_AVATAR,key,avatar);
		this.size=length;
	}
}

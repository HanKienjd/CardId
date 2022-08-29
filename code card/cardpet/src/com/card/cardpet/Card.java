package com.card.cardpet;
import javacard.security.AESKey;

public class Card {
	private final byte[] id;
	private final byte[] namePeople;
	private final byte[] namePet;
	private final byte[] dateOfBirth;
	private final byte[] numberPhone;
	private final byte[] remainingBalance;
	private final Avatar avatar;
	private final AES aes;
	public Card(){
		id=new byte[16];
		namePeople=new byte[16];
		namePet=new byte[16];
		dateOfBirth=new byte[16];
		numberPhone=new byte[16];
		remainingBalance=new byte[16];
		avatar=new Avatar();
		aes=new AES();
	}
	//get set Id
	//get gia tri thuoc tinh ta lay ban ma roi giai ma
	public short getId(AESKey key, byte[] buf, short offset) {
		//giai ma thong tin
	    return aes.decrypt(id, (short) 0, (short) id.length, key, buf, offset);
    }
    //khi set gia tri thuoc tinh, ta khong set ban ro, ta set ban ma
    public void setId(byte[] buf, short offset, short length, AESKey key) {
    	//ma hoa hinh anh
    	aes.encrypt(buf, offset, length, key, id);
    }
    
    //get set name people
    public short getNamePeople(AESKey key, byte[] buf, short offset) {
	    return aes.decrypt(namePeople, (short) 0, (short) namePeople.length, key, buf, offset);
    }

    public void setNamePeople(byte[] buf, short offset, short length, AESKey key) {
    	aes.encrypt(buf, offset, length, key, namePeople);
    }
    
    //get set name pet
    // public short getNamePet(AESKey key, byte[] buf, short offset) {
	    // return aes.decrypt(namePet, (short) 0, (short) namePet.length, key, buf, offset);
    // }

    // public void setNamePet(byte[] buf, short offset, short length, AESKey key) {
    	// aes.encrypt(buf, offset, length, key, namePet);
    // }
    
    //get set date of birth
    public short getDateOfBirth(AESKey key, byte[] buf, short offset) {
	    return aes.decrypt(dateOfBirth, (short) 0, (short) dateOfBirth.length, key, buf, offset);
    }

    public void setDateOfBirth(byte[] buf, short offset, short length, AESKey key) {
    	aes.encrypt(buf, offset, length, key, dateOfBirth);
    }
    
    //get set number phone
    public short getNumberPhone(AESKey key, byte[] buf, short offset) {
	    return aes.decrypt(numberPhone, (short) 0, (short) numberPhone.length, key, buf, offset);
    }

    public void setNumberPhone(byte[] buf, short offset, short length, AESKey key) {
    	aes.encrypt(buf, offset, length, key, numberPhone);
    }
    
    //get set remaining balance
    public short getRemainingBalance(AESKey key, byte[] buf, short offset) {
	    return aes.decrypt(remainingBalance, (short) 0, (short) remainingBalance.length, key, buf, offset);
    }

    public void setRemainingBalance(byte[] buf, short offset, short length, AESKey key) {
    	aes.encrypt(buf, offset, length, key, remainingBalance);
    }
    
    //get set avatar
    public short getAvatar(AESKey key, byte[] buf, short offset) {
	    return avatar.getAvatar(aes, key, buf, offset);
    }

    public void setAvatar(byte[] buf, short offset, short length, AESKey key) {
    	avatar.setAvatar(buf, offset, length, aes, key);
    }
}

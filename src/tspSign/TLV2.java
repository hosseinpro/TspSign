package tspSign;

import javacard.framework.*;

public class TLV2 {

	private static final short MAX_PATH_LEN = (short)40;
	
	public short[] Offset;
	public short[] Tag;
	public short[] Len;
	public short[] ValueIndex;
	
	public TLV2()
	{
		Offset = JCSystem.makeTransientShortArray(MAX_PATH_LEN, JCSystem.CLEAR_ON_DESELECT);
		Tag = JCSystem.makeTransientShortArray(MAX_PATH_LEN, JCSystem.CLEAR_ON_DESELECT);
		Len = JCSystem.makeTransientShortArray(MAX_PATH_LEN, JCSystem.CLEAR_ON_DESELECT);
		ValueIndex = JCSystem.makeTransientShortArray(MAX_PATH_LEN, JCSystem.CLEAR_ON_DESELECT);		
	}
	
	public void Parse(byte[] buff, short offset, byte[] path)
	{
		short pathLength = (short)path.length;
		
		if(pathLength > MAX_PATH_LEN){
			return;}
		
		short headerLen = 0;
		short len = 0;
		byte move = 0;
			
		for(short i=0; i<pathLength; i++)
		{
			move = path[i];
			if(move == 0x01){//child
				offset += headerLen;}
			else if(move == 0x02){//next
				offset += (short)(headerLen + len);}
			//else (move == 0x00){//no move(root)
			
			short bLen = Util.makeShort((byte)0, buff[(short)(offset + 1)]);
			if(bLen == 0x82){
				len = Util.makeShort(buff[(short)(offset + 2)], buff[(short)(offset + 3)]);
				headerLen = 4;/*Tag 82 XX XX*/}
			else if(bLen == 0x81){
				len = Util.makeShort((byte)0, buff[(short)(offset + 2)]);
				headerLen = 3;/*Tag 81 XX*/}
			else if(bLen < 0x80){
				len = bLen;
				headerLen = 2;/*Tag XX*/}	
			
			Offset[i] = offset;
			Tag[i] = Util.makeShort((byte)0, buff[offset]);
			Len[i] = len;
			ValueIndex[i] = (short)(offset + headerLen);
		}
	}
}

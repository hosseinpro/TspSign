package tspSign;

import javacard.framework.*;

public class TLV
{
	public short Tag;
	public short Len;
	public short ValueIndex;
	public short NextTagIndex;
	
	public TLV(){}
	
	public void Parse(byte[] buff, short offset)
	{
		short headerLen = 0;
		Tag = Util.makeShort((byte)0, buff[offset]);
		headerLen++;
		short bLen = Util.makeShort((byte)0, buff[(short)(offset + 1)]);
		if(bLen < 0x80){
			Len = bLen;
			headerLen++;}
		else if(bLen == 0x81){
			Len = Util.makeShort((byte)0, buff[(short)(offset + 2)]);
			headerLen+=2;}
		else{//bLen == 0x82
			Len = Util.makeShort(buff[(short)(offset + 2)], buff[(short)(offset + 3)]);
			headerLen+=3;}			
		ValueIndex = (short)(offset + headerLen);			
		NextTagIndex = (short)(ValueIndex + Len);
	}
}
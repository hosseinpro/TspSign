package tspSign;

import javacard.framework.*;

public class X509CRL {
	
	private static final byte[] pathCrl = {
										0x00,//CertificateList
											0x01, //TBSCertList
												0x01, //Version
												0x02, //AlgorithmIdentifier
												0x02, //issuer
												0x02, //thisUpdate
												0x02, //nextUpdate
												0x02, //revokedCertificates
												0x02, //crlExtensions
											0x02, //AlgorithmIdentifier
											0x02 //signatureValue
									};
	
	public short tbsCertListIndex = 0;
	public short tbsCertListLen = 0;
	public short signatureIndex = 0;
	public short signatureLen = 0;
	
	public byte[] thisUpdate;
	public byte[] nextUpdate;
	
	private short[] revokedCertsIndexes = null;	
	
	private TLV tlv;
	private TLV2 tlv2;
	
	public X509CRL()
	{
		thisUpdate = new byte[12];
		nextUpdate = new byte[12];
		tlv = new TLV();
		tlv2 = new TLV2();		
	}
	
	public void Parse(byte[] bytesCRL, short offset)
	{
	    /*CertificateList  ::=  SEQUENCE  {
			tbsCertList          TBSCertList,
			signatureAlgorithm   AlgorithmIdentifier,
			signatureValue       BIT STRING  }*/		
		//TLV tlv = new TLV();
		tlv.Parse(bytesCRL, offset);
		tbsCertListIndex = tlv.ValueIndex;
		tlv.Parse(bytesCRL, tbsCertListIndex);
		short signatureAlgorithmIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCRL, signatureAlgorithmIndex);
		signatureIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCRL, signatureIndex);
		
		/*TBSCertList  ::=  SEQUENCE  {
			version                 Version OPTIONAL,
										 -- if present, MUST be v2
			AlgorithmIdentifier     AlgorithmIdentifier,
			issuer                  Name,
			thisUpdate              Time,
			nextUpdate              Time OPTIONAL,
			revokedCertificates     SEQUENCE OF SEQUENCE  {
				 userCertificate         CertificateSerialNumber,
				 revocationDate          Time,
				 crlEntryExtensions      Extensions OPTIONAL
										  -- if present, version MUST be v2
									  }  OPTIONAL,
			crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
										  -- if present, version MUST be v2
									  }*/
		tlv.Parse(bytesCRL, tbsCertListIndex);
		short versionIndex = tlv.ValueIndex;
		short algorithmIdentifierIndex = 0;
		tlv.Parse(bytesCRL, versionIndex);
		if(tlv.Tag == 0x02){//v2
			algorithmIdentifierIndex = tlv.NextTagIndex;
			tlv.Parse(bytesCRL, tlv.NextTagIndex);
			}
		else{//v1
			algorithmIdentifierIndex = versionIndex;
			versionIndex = 0;
			}
		short issuerIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCRL, issuerIndex);
		short thisUpdateIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCRL, thisUpdateIndex);
		short nextUpdateIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCRL, nextUpdateIndex);
		short revokedCertificatesIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCRL, revokedCertificatesIndex);
		short crlExtensionsIndex = tlv.NextTagIndex;
		if(tlv.Tag == 0xA0){//Empty CRL
			crlExtensionsIndex = revokedCertificatesIndex;
			revokedCertificatesIndex = 0;
		}
		
		//Fill thisUpdate and nextUpdate
		tlv.Parse(bytesCRL, thisUpdateIndex);		
		Util.arrayCopy(bytesCRL, tlv.ValueIndex, thisUpdate, (short)0, (short)12);
		tlv.Parse(bytesCRL, nextUpdateIndex);
		Util.arrayCopy(bytesCRL, tlv.ValueIndex, nextUpdate, (short)0, (short)12);
		
		//Fill signature
		tlv.Parse(bytesCRL, signatureIndex);
		signatureIndex = (short)(tlv.ValueIndex + 1);//Ignore first 00
		signatureLen = (short)(tlv.Len - 1);
		
		//Calculate signedpart
		tlv.Parse(bytesCRL, tbsCertListIndex);
		tbsCertListLen = (short)(tlv.NextTagIndex - tbsCertListIndex);//Include header
		
		
		//Extract revoked certs' serial numbers
		if(revokedCertificatesIndex == 0){
			//revokedCertsIndexes = new short[0];
			revokedCertsIndexes = JCSystem.makeTransientShortArray((short)0, JCSystem.CLEAR_ON_DESELECT);
			return;}
		
		short revokedCertsCount = (short)0;
		tlv.Parse(bytesCRL, revokedCertificatesIndex);
		tlv.Parse(bytesCRL, tlv.ValueIndex);
		revokedCertsCount++;
		while(tlv.NextTagIndex < crlExtensionsIndex)
		{
			tlv.Parse(bytesCRL, tlv.NextTagIndex);
			revokedCertsCount++;			
		}		
		
		revokedCertsIndexes = JCSystem.makeTransientShortArray(revokedCertsCount, JCSystem.CLEAR_ON_DESELECT);
		tlv.Parse(bytesCRL, revokedCertificatesIndex);
		tlv.Parse(bytesCRL, tlv.ValueIndex);
		for(short i=0; i<revokedCertsCount; i++)
		{
			revokedCertsIndexes[i] = tlv.ValueIndex;
			tlv.Parse(bytesCRL, tlv.NextTagIndex);			
		}
	}
	
	public boolean isRevoked(byte[] bytesCRL, short offset, byte[] serialNumber)
	{			
		for(short i=0; i<revokedCertsIndexes.length; i++)
		{
			tlv.Parse(bytesCRL, revokedCertsIndexes[i]);
			if((short)(tlv.Len - 1) == (short)(serialNumber.length)){
				if(Util.arrayCompare(serialNumber, (short)0, bytesCRL, (short)(tlv.ValueIndex + 1), (short)(tlv.Len - 1)) == 0){
					return true;}}
		}
		
		return false;
	}
	
	public void Parse(byte[] bytesCRL, short offset, boolean fast)
	{		
		tlv2.Parse(bytesCRL, offset, pathCrl);
		
		tbsCertListIndex = tlv2.Offset[1];
		signatureIndex = tlv2.Offset[10];
		short revokedCertificatesIndex = tlv2.Offset[7];
		short crlExtensionsIndex = tlv2.Offset[8];
		
		//Fill thisUpdate and nextUpdate
		Util.arrayCopy(bytesCRL, tlv2.ValueIndex[5], thisUpdate, (short)0, (short)12);
		Util.arrayCopy(bytesCRL, tlv2.ValueIndex[6], nextUpdate, (short)0, (short)12);
		
		//Fill signature
		signatureIndex = (short)(tlv2.ValueIndex[10] + 1);//Ignore first 00
		signatureLen = (short)(tlv2.Len[10] - 1);
		
		//Calculate signedpart
		tbsCertListLen = (short)(tlv2.Offset[9] - tbsCertListIndex);//Include header
		
		//Extract revoked certs' serial numbers
		if(revokedCertificatesIndex == 0){
			revokedCertsIndexes = JCSystem.makeTransientShortArray((short)0, JCSystem.CLEAR_ON_DESELECT);
			return;}		
		
		short revokedCertsCount = (short)0;
		tlv.Parse(bytesCRL, revokedCertificatesIndex);
		tlv.Parse(bytesCRL, tlv.ValueIndex);
		revokedCertsCount++;
		while(tlv.NextTagIndex < crlExtensionsIndex)
		{
			tlv.Parse(bytesCRL, tlv.NextTagIndex);
			revokedCertsCount++;			
		}
		
		revokedCertsIndexes = JCSystem.makeTransientShortArray(revokedCertsCount, JCSystem.CLEAR_ON_DESELECT);
		tlv.Parse(bytesCRL, revokedCertificatesIndex);
		tlv.Parse(bytesCRL, tlv.ValueIndex);
		for(short i=0; i<revokedCertsCount; i++)
		{
			revokedCertsIndexes[i] = tlv.ValueIndex;
			tlv.Parse(bytesCRL, tlv.NextTagIndex);		
		}
	}
}

package tspSign;

import javacard.framework.*;

public class TimeStampResp {
	
	private static final byte[] pathTSRCommand = {
				0x00,//TimeStampResp
					0x01, //PKIStatusInfo
					0x02, //TimeStampToken (ContentInfo)
						0x01, //ContentType
						0x02, //content [0]
							0x01, //SignedData
								0x01, //CMSVersion
								0x02, //DigestAlgorithmIdentifiers
								0x02, //EncapsulatedContentInfo
									0x01, //ContentType
									0x02, //eContent [0]
										0x01, //octetStringTypeIndex
											0x01, //TSTInfo
												0x01, //version
												0x02, //TSAPolicyId
												0x02, //MessageImprint
													0x01, //hashAlgorithm
													0x02, //hashedMessage
												0x02, //serialNumber
												0x02, //genTime
												0x02, //nonce
								0x02, //certificates [0]
									0x01, //certificate
								0x02, //crls [1]
									0x01, //crl
								0x02, //SignerInfos
									0x01, //SignerInfo
										0x01, //CMSVersion
										0x02, //SignerIdentifier
										0x02, //DigestAlgorithmIdentifier
										0x02, //signedAttrs [0]
										0x02, //SignatureAlgorithmIdentifier
										0x02 //SignatureValue
			};
			
	private static final byte[] pathTSRResponse = {
				0x00,//TimeStampResp
					0x01, //PKIStatusInfo
					0x02, //TimeStampToken (ContentInfo)
						0x01, //ContentType
						0x02, //content [0]
							0x01, //SignedData
								0x01, //CMSVersion
								0x02, //DigestAlgorithmIdentifiers
								0x02, //EncapsulatedContentInfo
									0x01, //ContentType
									0x02, //eContent [0]
										0x01, //octetStringTypeIndex
											0x01, //TSTInfo
												0x01, //version
												0x02, //TSAPolicyId
												0x02, //MessageImprint
													0x01, //hashAlgorithm
													0x02, //hashedMessage
												0x02, //serialNumber
												0x02, //genTime
												//0x02, //nonce
								0x02, //certificates [0]
									0x01, //certificate
								//0x02, //crls [1]
									//0x01, //crl
								0x02, //SignerInfos
									0x01, //SignerInfo
										0x01, //CMSVersion
										0x02, //SignerIdentifier
										0x02, //DigestAlgorithmIdentifier
										0x02, //signedAttrs [0]
										0x02, //SignatureAlgorithmIdentifier
										0x02 //SignatureValue
			};
				
	public byte[] nonce = null;
	public byte[] time;
	public byte[] hash;
	
	public short timeIndex = 0;//Fix len 14 (yyyyMMddhhmmss)
	public short hashIndex = 0;//Fix len 20 (SHA1)
	public short nonceIndex = 0;
	
	public short certificateIndex = 0;
	public short crlIndex = 0;
	
	public short tstInfoIndex = 0;
	public short tstInfoLen = 0;
	public short signatureIndex = 0;
	public short signatureLen = 0;
	
	private TLV tlv;
	private TLV2 tlv2;
		
	public TimeStampResp()
	{
		time = new byte[14];
		hash = new byte[20];
		
		tlv = new TLV();
		tlv2 = new TLV2();	
	}
						
	public void Parse(byte[] bytesTimeStampResp, short offset)
	{
		/*TimeStampResp ::= SEQUENCE  {
			status                  PKIStatusInfo,
			timeStampToken          TimeStampToken     OPTIONAL  }*/
		tlv.Parse(bytesTimeStampResp, offset);
		short statusIndex = tlv.ValueIndex;
		tlv.Parse(bytesTimeStampResp, statusIndex);
		short timeStampTokenIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, timeStampTokenIndex);
		
		/*TimeStampToken ::= ContentInfo
		ContentInfo ::= SEQUENCE {
			contentType ContentType,
			content [0] EXPLICIT ANY DEFINED BY contentType }*/
		short contentTypeIndex = tlv.ValueIndex;
		tlv.Parse(bytesTimeStampResp, contentTypeIndex);		
		short contentIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, contentIndex);
		short signedDataIndex = tlv.ValueIndex;
		tlv.Parse(bytesTimeStampResp, signedDataIndex);	
		
		/*SignedData ::= SEQUENCE {
			version CMSVersion,
			digestAlgorithms DigestAlgorithmIdentifiers,
			encapContentInfo EncapsulatedContentInfo,
			certificates [0] IMPLICIT CertificateSet OPTIONAL, //Mandatory
			crls [1] IMPLICIT RevocationInfoChoices OPTIONAL, //Optional
			signerInfos SignerInfos }*/
		short cmsVersionIndex = tlv.ValueIndex;
		tlv.Parse(bytesTimeStampResp, cmsVersionIndex);		
		short digestAlgorithmsIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, digestAlgorithmsIndex);
		short encapContentInfoIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, encapContentInfoIndex);		
		short certificatesIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, certificatesIndex);		
		short crlsIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, crlsIndex);
		short signerInfosIndex = 0;
		if(tlv.Tag != 0xA1){//no CRL
			signerInfosIndex = crlsIndex;
			crlsIndex = 0;
		}
		else{
			signerInfosIndex = tlv.NextTagIndex;
			tlv.Parse(bytesTimeStampResp, signerInfosIndex);
		}
				
		/*EncapsulatedContentInfo ::= SEQUENCE {
			eContentType ContentType,
			eContent [0] EXPLICIT OCTET STRING OPTIONAL }*/
		tlv.Parse(bytesTimeStampResp, encapContentInfoIndex);
		short eContentTypeIndex = tlv.ValueIndex;
		tlv.Parse(bytesTimeStampResp, eContentTypeIndex);
		short eContentIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, eContentIndex);		

		short octetStringTypeIndex = tlv.ValueIndex;		
		tlv.Parse(bytesTimeStampResp, octetStringTypeIndex);
		tstInfoIndex = tlv.ValueIndex;		
		tlv.Parse(bytesTimeStampResp, tstInfoIndex);
		
		/*TSTInfo ::= SEQUENCE  {
			version                      INTEGER  { v1(1) },
			policy                       TSAPolicyId,
			messageImprint               MessageImprint,
			-- MUST have the same value as the similar field in
			-- TimeStampReq
			serialNumber                 INTEGER,
			-- Time-Stamping users MUST be ready to accommodate integers
			-- up to 160 bits.
			genTime                      GeneralizedTime,
			accuracy                     Accuracy                 OPTIONAL,
			ordering                     BOOLEAN             DEFAULT FALSE,
			nonce                        INTEGER                  OPTIONAL,
			-- MUST be present if the similar field was present
			-- in TimeStampReq.  In that case it MUST have the same value.
			tsa                          [0] GeneralName          OPTIONAL,
			extensions                   [1] IMPLICIT Extensions   OPTIONAL  }*/
		short tstVersionIndex = tlv.ValueIndex;		
		tlv.Parse(bytesTimeStampResp, tstVersionIndex);
		short policyIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, policyIndex);		
		short messageImprintIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, messageImprintIndex);			
		short serialNumberIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, serialNumberIndex);			
		short genTimeIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, genTimeIndex);		
		nonceIndex = tlv.NextTagIndex;
		tlv.Parse(bytesTimeStampResp, nonceIndex);
		if(tlv.Tag != 0x02){//no nonce
			nonceIndex = 0;}
		
		/*SignerInfo ::= SEQUENCE {
			version CMSVersion,
			sid SignerIdentifier,
			digestAlgorithm DigestAlgorithmIdentifier,
			signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
			signatureAlgorithm SignatureAlgorithmIdentifier,
			signature SignatureValue,
			unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }*/
		tlv.Parse(bytesTimeStampResp, signerInfosIndex);
		short signerInfoIndex = tlv.ValueIndex;
		tlv.Parse(bytesTimeStampResp, signerInfoIndex);
		tlv.Parse(bytesTimeStampResp, tlv.ValueIndex);
		tlv.Parse(bytesTimeStampResp, tlv.NextTagIndex);
		tlv.Parse(bytesTimeStampResp, tlv.NextTagIndex);
		tlv.Parse(bytesTimeStampResp, tlv.NextTagIndex);
		tlv.Parse(bytesTimeStampResp, tlv.NextTagIndex);
		tlv.Parse(bytesTimeStampResp, tlv.NextTagIndex);
		signatureIndex = tlv.ValueIndex;
		signatureLen = tlv.Len;
		
		//Fill nonce
		if(nonceIndex != 0)
		{
			tlv.Parse(bytesTimeStampResp, nonceIndex);
			//nonce = new byte[tlv.Len];
			nonce = JCSystem.makeTransientByteArray(tlv.Len, JCSystem.CLEAR_ON_DESELECT);
			Util.arrayCopy(bytesTimeStampResp, tlv.ValueIndex, nonce, (short)0, tlv.Len);
		}
		
		//Fill time
		tlv.Parse(bytesTimeStampResp, genTimeIndex);
		timeIndex = tlv.ValueIndex;
		Util.arrayCopy(bytesTimeStampResp, timeIndex, time, (short)0, (short)14);
		
		//Fill hash
		tlv.Parse(bytesTimeStampResp, messageImprintIndex);
		/*MessageImprint ::= SEQUENCE  {
			hashAlgorithm                AlgorithmIdentifier,
			hashedMessage                OCTET STRING  }*/
		short hashAlgorithmIndex = tlv.ValueIndex;
		tlv.Parse(bytesTimeStampResp, hashAlgorithmIndex);
		short hashedMessageIndex = tlv.NextTagIndex;		
		tlv.Parse(bytesTimeStampResp, hashedMessageIndex);
		hashIndex = tlv.ValueIndex;
		Util.arrayCopy(bytesTimeStampResp, hashIndex, hash, (short)0, (short)20);
		
		//Fill certificateIndex
		tlv.Parse(bytesTimeStampResp, certificatesIndex);
		certificateIndex = tlv.ValueIndex;

		//Fill crlIndex		
		if(crlsIndex != 0)
		{
			tlv.Parse(bytesTimeStampResp, crlsIndex);
			crlIndex = tlv.ValueIndex;			
		}				
		
		//Calculate signedpart
		tlv.Parse(bytesTimeStampResp, tstInfoIndex);
		tstInfoLen = (short)(tlv.NextTagIndex - tstInfoIndex);//Include header	
	}
	
	public void Parse(byte[] bytesTimeStampResp, short offset, boolean command)
	{
		if(command == true)
		{					
			tlv2.Parse(bytesTimeStampResp, offset, pathTSRCommand);
			
			tstInfoIndex = tlv2.Offset[12];
			short hashedMessageIndex = tlv2.Offset[17]; 
			short genTimeIndex = tlv2.Offset[19];
			nonceIndex = tlv2.Offset[20];
			certificateIndex = tlv2.Offset[22];
			crlIndex = tlv2.Offset[24];
			
			//Fill nonce
			nonce = JCSystem.makeTransientByteArray(tlv2.Len[20], JCSystem.CLEAR_ON_DESELECT);
			Util.arrayCopy(bytesTimeStampResp, tlv2.ValueIndex[20], nonce, (short)0, tlv2.Len[20]);
			
			//Fill time
			timeIndex = tlv2.ValueIndex[19];
			Util.arrayCopy(bytesTimeStampResp, timeIndex, time, (short)0, (short)14);
			
			//Fill hash
			hashIndex = tlv2.ValueIndex[17];
			Util.arrayCopy(bytesTimeStampResp, hashIndex, hash, (short)0, (short)20);			
			
			//Calculate signedpart
			tstInfoLen = (short)(tlv2.Offset[21] - tstInfoIndex);//Include header
			
			//Fill signature
			signatureIndex = tlv2.ValueIndex[32];
			signatureLen = tlv2.Len[32];
		}
		else//response
		{					
			tlv2.Parse(bytesTimeStampResp, offset, pathTSRResponse);
			
			tstInfoIndex = tlv2.Offset[12];
			nonceIndex = 0;
			certificateIndex = tlv2.Offset[21];
			crlIndex = 0;
			
			//Fill nonce
			nonce = null;
			
			//Fill time
			timeIndex = tlv2.ValueIndex[19];	
			Util.arrayCopy(bytesTimeStampResp, timeIndex, time, (short)0, (short)14);
			
			//Fill hash
			hashIndex = tlv2.ValueIndex[17];
			Util.arrayCopy(bytesTimeStampResp, hashIndex, hash, (short)0, (short)20);			
			
			//Calculate signedpart
			tstInfoLen = (short)(tlv2.Offset[20] - tstInfoIndex);//Include header
			
			//Fill signature
			signatureIndex = tlv2.ValueIndex[29];
			signatureLen = tlv2.Len[29];
		}
	}
}

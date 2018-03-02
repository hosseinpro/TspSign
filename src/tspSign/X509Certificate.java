package tspSign;

import javacard.framework.*;

public class X509Certificate {
	
	private static final byte[] pathCertificate = {
						0x00,//Certificate
							0x01, //TBSCertificate
								0x01, //Version
								0x02, //CertificateSerialNumber
								0x02, //AlgorithmIdentifier
								0x02, //issuer
								0x02, //Validity
									0x01, //notBefore
									0x02, //notAfter
								0x02, //subject
								0x02, //SubjectPublicKeyInfo
									0x01, //AlgorithmIdentifier
									0x02, //subjectPublicKey
										//0x01, //PublicKey
											//0x01, //Modulus
											//0x02, //Exponent
								0x02, //Extensions
							0x02, //AlgorithmIdentifier
							0x02 //signature
					};
					
	private static final byte[] pathPublicKey = {
						0x00, //PublicKey
							0x01, //Modulus
							0x02 //Exponent
						};
	
	public short tbsCertificateIndex = 0;
	public short tbsCertificateLen = 0;
	public short signatureIndex = 0;
	public short signatureLen = 0;
	
	public byte[] serialNumber;
	public byte[] notBefore;
	public byte[] notAfter;
	public short publicKeyModulusIndex = 0;
	public short publicKeyModulusLen = 0;
	public short publicKeyExponentIndex = 0;
	public short publicKeyExponentLen = 0;
	
	private TLV tlv;
	private TLV2 tlv2;
	
	public X509Certificate()
	{
		notBefore = new byte[12];
		notAfter = new byte[12];
		
		tlv = new TLV();
		tlv2 = new TLV2();
	}
	
	public void Parse(byte[] bytesCertificate, short offset)
	{
		/*Certificate  ::=  SEQUENCE  {
			 tbsCertificate       TBSCertificate,
			 signatureAlgorithm   AlgorithmIdentifier,
			 signature            BIT STRING  }*/		
		//TLV tlv = new TLV();
		tlv.Parse(bytesCertificate, offset);
		tbsCertificateIndex = tlv.ValueIndex;
		tlv.Parse(bytesCertificate, tbsCertificateIndex);
		short signatureAlgorithmIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCertificate, signatureAlgorithmIndex);
		signatureIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCertificate, signatureIndex);
		
		/*TBSCertificate  ::=  SEQUENCE  {
			 version         [0]  EXPLICIT Version DEFAULT v1,
			 serialNumber         CertificateSerialNumber,
			 algorithmIdentifier  AlgorithmIdentifier,
			 issuer               Name,
			 validity             Validity,
			 subject              Name,
			 subjectPublicKeyInfo SubjectPublicKeyInfo,
			 issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
								  -- If present, version must be v2 or v3
			 subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
								  -- If present, version must be v2 or v3
			 extensions      [3]  EXPLICIT Extensions OPTIONAL
								  -- If present, version must be v3
			 }*/			 
		tlv.Parse(bytesCertificate, tbsCertificateIndex);
		short versionIndex = tlv.ValueIndex;
		short serialNumberIndex = 0;
		tlv.Parse(bytesCertificate, versionIndex);
		if(tlv.Tag == 0xA0){//v2 and v3
			serialNumberIndex = tlv.NextTagIndex;
			tlv.Parse(bytesCertificate, tlv.NextTagIndex);
			}
		else{//v1
			serialNumberIndex = versionIndex;
			versionIndex = 0;
			}
		short algorithmIdentifierIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCertificate, algorithmIdentifierIndex);
		short issuerIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCertificate, issuerIndex);
		short validityIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCertificate, validityIndex);
		short subjectIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCertificate, subjectIndex);
		short subjectPublicKeyInfoIndex = tlv.NextTagIndex;
		tlv.Parse(bytesCertificate, subjectPublicKeyInfoIndex);
		
		//Fill serialNumber
		tlv.Parse(bytesCertificate, serialNumberIndex);
		serialNumber = JCSystem.makeTransientByteArray((short)(tlv.Len - 1), JCSystem.CLEAR_ON_DESELECT);
		Util.arrayCopy(bytesCertificate, (short)(tlv.ValueIndex + 1), serialNumber, (short)0, (short)(tlv.Len - 1));		
		
		//Fill notBefore and notAfter
		tlv.Parse(bytesCertificate, validityIndex);
		tlv.Parse(bytesCertificate, tlv.ValueIndex);
		Util.arrayCopy(bytesCertificate, tlv.ValueIndex, notBefore, (short)0, (short)12);
		tlv.Parse(bytesCertificate, tlv.NextTagIndex);
		Util.arrayCopy(bytesCertificate, tlv.ValueIndex, notAfter, (short)0, (short)12);
		
		//Fill modulus and exponent
		tlv.Parse(bytesCertificate, subjectPublicKeyInfoIndex);//-> 30 81 9F
		tlv.Parse(bytesCertificate, tlv.ValueIndex);//-> 30 0D
		tlv.Parse(bytesCertificate, tlv.NextTagIndex);//-> 03 81 8D 00
		tlv.Parse(bytesCertificate, (short)(tlv.ValueIndex + 1));//-> 30 81 89
		tlv.Parse(bytesCertificate, tlv.ValueIndex);//-> 02 81 81
		publicKeyModulusIndex = (short)(tlv.ValueIndex + 1);
		publicKeyModulusLen = (short)(tlv.Len - 1);
		tlv.Parse(bytesCertificate, tlv.NextTagIndex);//-> 02 03
		publicKeyExponentIndex = tlv.ValueIndex;
		publicKeyExponentLen = tlv.Len;
		
		//Fill signature
		tlv.Parse(bytesCertificate, signatureIndex);
		signatureIndex = (short)(tlv.ValueIndex + 1);//Ignore first 00
		signatureLen = (short)(tlv.Len - 1);
		
		//Calculate signedpart
		tlv.Parse(bytesCertificate, tbsCertificateIndex);
		tbsCertificateLen = (short)(tlv.NextTagIndex - tbsCertificateIndex);//Include header
	}

	public void Parse(byte[] bytesCertificate, short offset, boolean fast)
	{	
		//TLV2 tlv2 = new TLV2();
		tlv2.Parse(bytesCertificate, offset, pathCertificate);
		
		tbsCertificateIndex = tlv2.Offset[1];
		short serialNumberIndex = tlv2.Offset[3];
		short validityIndex = tlv2.Offset[6];
		short subjectPublicKeyInfoIndex = tlv2.Offset[10];
		signatureIndex = tlv2.Offset[15];
		short publicKeyIndex = (short)(tlv2.ValueIndex[12] + 1);//ignore 00 !
		
		//Fill serialNumber
		serialNumber = JCSystem.makeTransientByteArray((short)(tlv2.Len[3] - 1), JCSystem.CLEAR_ON_DESELECT);
		Util.arrayCopy(bytesCertificate, (short)(tlv2.ValueIndex[3] + 1), serialNumber, (short)0, (short)(tlv2.Len[3] - 1));		
		
		//Fill notBefore and notAfter
		Util.arrayCopy(bytesCertificate, tlv2.ValueIndex[7], notBefore, (short)0, (short)12);
		Util.arrayCopy(bytesCertificate, tlv2.ValueIndex[8], notAfter, (short)0, (short)12);
		
		//Calculate signedpart
		tbsCertificateLen = (short)(tlv2.Offset[14] - tbsCertificateIndex);//Include header
		
		//Fill signature
		signatureIndex = (short)(tlv2.ValueIndex[15] + 1);//Ignore first 00
		signatureLen = (short)(tlv2.Len[15] - 1);
		
		tlv2.Parse(bytesCertificate, publicKeyIndex, pathPublicKey);
								
		publicKeyModulusIndex = (short)(tlv2.ValueIndex[1] + 1);
		publicKeyModulusLen = (short)(tlv2.Len[1] - 1);
		publicKeyExponentIndex = tlv2.ValueIndex[2];
		publicKeyExponentLen = tlv2.Len[2];
	}
}

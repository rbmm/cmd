#include "stdafx.h"

//==============================================================================
//
// ASN.1 constructs
//
//==============================================================================

#define ASN_TAG(c, p, t) ((ULONG)( static_cast<int>(c) | static_cast<int>(p) | static_cast<int>(t) ))
#define ASN_INDEX(i)	ASN_TAG(ctContextSpecific, pcConstructed, i)
#define SEQUENCE		ASN_TAG(ctUniversal, pcConstructed, utSequence)
#define ASN_APP(a)		ASN_TAG(ctApplication, pcConstructed, a)
#define ASN_DATA(t)		ASN_TAG(ctUniversal, pcPrimitive, t)

//
// Class tags
//

enum ClassTag
{
	ctUniversal          =  0x00, // 00000000
	ctApplication        =  0x40, // 01000000
	ctContextSpecific    =  0x80, // 10000000
	ctPrivate            =  0xC0, // 11000000
};

//
// Primitive-Constructed
//

enum PC
{
	pcPrimitive          = 0x00, // 00000000
	pcConstructed        = 0x20, // 00100000
};

enum UniversalTag
{
	utBoolean            = 0x01, // 00001
	utInteger            = 0x02, // 00010
	utBitString          = 0x03, // 00011
	utOctetString        = 0x04, // 00100
	utNULL               = 0x05, // 00101
	utObjectIdentifer    = 0x06, // 00110
	utObjectDescriptor   = 0x07, // 00111
	utExternal           = 0x08, // 01000
	utReal               = 0x09, // 01001
	utEnumerated         = 0x0A, // 01010
	utSequence           = 0x10, // 10000
	utSet                = 0x11, // 10001
	utNumericString      = 0x12, // 10010
	utPrintableString    = 0x13, // 10011
	utT61String          = 0x14, // 10100
	utVideotexString     = 0x15, // 10101
	utIA5String          = 0x16, // 10110
	utUTCTime            = 0x17, // 10111
	utGeneralizedTime    = 0x18, // 11000
	utGraphicString      = 0x19, // 11001
	utVisibleString      = 0x1A, // 11010
	utGeneralString      = 0x1B, // 11011
	utUniversalString    = 0x1C,
	utCharString         = 0x1D,
	utBMPString          = 0x1E,
};

typedef signed char SCHAR;

#define szOID_PKCS_12_SHROUDEDKEY_BAG "1.2.840.113549.1.12.10.1.2"

const BYTE* GetShrouedKeyBag(const BYTE* pbBuffer, ULONG cbLength, _Out_ PDATA_BLOB pdb)
{
	BOOLEAN bBag = FALSE;

	if (cbLength)
	{
		union {
			ULONG Len;
			struct {
				SCHAR l_0;
				SCHAR l_1;
				SCHAR l_2;
				SCHAR l_3;
			};
		};

		do 
		{
			const BYTE* pb = pbBuffer;
			ULONG cb = cbLength;

			union {
				ULONG uTag;
				struct {
					SCHAR t_0;
					SCHAR t_1;
					SCHAR t_2;
					SCHAR t_3;
				};
				struct {
					UCHAR tag : 5;
					UCHAR composite : 1;
					UCHAR cls : 2;
				};
			};

			uTag = *pbBuffer++, cbLength--;

			if (tag == 0x1F)
			{
				if (!cbLength--)
				{
					return 0;
				}

				if (0 > (t_1 = *pbBuffer++))
				{
					if (!cbLength--)
					{
						return 0;
					}

					if (0 > (t_2 = *pbBuffer++))
					{
						if (!cbLength--)
						{
							return 0;
						}

						t_3 = *pbBuffer++;
					}
				}
			}

			if (!uTag)
			{
				Len = 0;
				continue;
			}

			if (!cbLength--)
			{
				return 0;
			}

			Len = *pbBuffer++;

			if (0 > l_0)
			{
				if ((Len &= ~0x80) > cbLength)
				{
					return 0;
				}

				cbLength -= Len;

				switch (Len)
				{
				case 4:
					l_3 = *pbBuffer++;
					l_2 = *pbBuffer++;
				case 2:
					l_1 = *pbBuffer++;
				case 1:
					l_0 = *pbBuffer++;
				case 0:
					break;
				default: return 0;
				}
			}

			if (Len > cbLength)
			{
				return 0;
			}

			if (bBag)
			{
				bBag = FALSE;

				if (pdb->pbData)
				{
					return 0;
				}

				pdb->pbData = const_cast<PBYTE>(pbBuffer);
				pdb->cbData = Len;
			}

			ULONG cbStructInfo;
			union {
				PVOID pvStructInfo;
				PSTR* ppszObjId;
			};

			switch (uTag)
			{
			case ASN_TAG(ctUniversal, pcPrimitive, utObjectIdentifer):
				if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_OBJECT_IDENTIFIER, 
					pb, cb, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 0, &ppszObjId, &cbStructInfo))
				{
					bBag = !strcmp(*ppszObjId, szOID_PKCS_12_SHROUDEDKEY_BAG);

					LocalFree(ppszObjId);
				}
				break;

			case ASN_TAG(ctUniversal, pcPrimitive, utOctetString):
				if (Len > 32)
				{
					GetShrouedKeyBag(pbBuffer, Len, pdb);
				}
				break;
			}

			if (composite)
			{
				if (!GetShrouedKeyBag(pbBuffer, Len, pdb)) return 0;
			}

		} while (pbBuffer += Len, cbLength -= Len);
	}

	return pbBuffer;
}
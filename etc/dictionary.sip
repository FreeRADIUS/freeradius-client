#
# Updated 97/06/13 to livingston-radius-2.01 miquels@cistron.nl
#
#	This file contains dictionary translations for parsing
#	requests and generating responses.  All transactions are
#	composed of Attribute/Value Pairs.  The value of each attribute
#	is specified as one of 4 data types.  Valid data types are:
#
#	string - 0-253 octets
#	ipaddr - 4 octets in network byte order
#	integer - 32 bit value in big endian order (high byte first)
#	date - 32 bit value in big endian order - seconds since
#					00:00:00 GMT,  Jan.  1,  1970
#
#	Enumerated values are stored in the user file with dictionary
#	VALUE translations for easy administration.
#
#	Example:
#
#	ATTRIBUTE	  VALUE
#	---------------   -----
#	Framed-Protocol = PPP
#	7		= 1	(integer encoding)
#

#
#	Experimental SIP Attributes/Values (draft-sterman-aaa-sip-00.txt etc)
#
ATTRIBUTE	Sip-Method		101	integer
ATTRIBUTE	Sip-Response-Code	102	integer
ATTRIBUTE	Sip-CSeq		103	string
ATTRIBUTE	Sip-To-Tag		104	string
ATTRIBUTE	Sip-From-Tag		105	string
ATTRIBUTE	Sip-Branch-ID		106	string
ATTRIBUTE	Sip-Translated-Request-URI	107	string
ATTRIBUTE	Sip-Source-IP-Address	108	ipaddr
ATTRIBUTE	Sip-Source-Port		109	integer
ATTRIBUTE	Sip-User-ID		110	string
ATTRIBUTE	Sip-User-Realm		111	string
ATTRIBUTE	Sip-User-Nonce		112	string
ATTRIBUTE	Sip-User-Method		113	string
ATTRIBUTE	Sip-User-Digest-URI	114	string
ATTRIBUTE	Sip-User-Nonce-Count	115	string
ATTRIBUTE	Sip-User-QOP		116	string
ATTRIBUTE	Sip-User-Opaque		117	string
ATTRIBUTE	Sip-User-Response	118	string
ATTRIBUTE	Sip-User-CNonce		119	string
ATTRIBUTE	Sip-URI-User		208	string
ATTRIBUTE	Sip-Req-URI		210	string
ATTRIBUTE	Sip-CC			212	string
ATTRIBUTE	Sip-RPId		213	string
ATTRIBUTE	Digest-Response		206	string
ATTRIBUTE	Digest-Attributes	207	string
ATTRIBUTE	Digest-Realm		1063	string
ATTRIBUTE	Digest-Nonce		1064	string
ATTRIBUTE	Digest-Method		1065	string
ATTRIBUTE	Digest-URI		1066	string
ATTRIBUTE	Digest-QOP		1067	string
ATTRIBUTE	Digest-Algorithm	1068	string
ATTRIBUTE	Digest-Body-Digest	1069	string
ATTRIBUTE	Digest-CNonce		1070	string
ATTRIBUTE	Digest-Nonce-Count	1071	string
ATTRIBUTE	Digest-User-Name	1072	string

VALUE		Service-Type		SIP			15

VALUE		Sip-Method		Other			0
VALUE		Sip-Method		Invite			1
VALUE		Sip-Method		Cancel			2
VALUE		Sip-Method		Ack			3
VALUE		Sip-Method		Bye			4

VALUE		Sip-Response-Code	Other			0
VALUE		Sip-Response-Code	Invite			1
VALUE		Sip-Response-Code	Cancel			2
VALUE		Sip-Response-Code	Ack			3
VALUE		Sip-Response-Code	Bye			4

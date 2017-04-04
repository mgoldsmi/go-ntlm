package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAddAvPairs(t *testing.T) {

	avPairs := new(AvPairs)

	// Test empty list
	result := avPairs.Bytes()
	expected, _ := hex.DecodeString("00000000")
	if !bytes.Equal(result, expected) {
		t.Errorf("Test empty list is not correct got %s expected %s", hex.EncodeToString(result), "00000000")
	}

	// Add MsvAvNbComputerName
	avPairs.AddAvPair(MsvAvNbComputerName, utf16FromString("Server"))
	result = avPairs.Bytes()
	expected, _ = hex.DecodeString("01000c0053006500720076006500720000000000")
	if !bytes.Equal(result, expected) {
		t.Errorf("Add MsvAvNbComputerName is not correct got %s expected %s", hex.EncodeToString(result), "01000c0053006500720076006500720000000000")
	}

	// Attempt to add MsAvEOL
	avPairs.AddAvPair(MsvAvEOL, make([]byte, 0))
	result = avPairs.Bytes()
	expected, _ = hex.DecodeString("01000c0053006500720076006500720000000000")
	if !bytes.Equal(result, expected) {
		t.Errorf("Attempt to add MsAvEOL is not correct got %s expected %s", hex.EncodeToString(result), "01000c0053006500720076006500720000000000")
	}

	// Add MsvAvFlags
	avPairs.AddAvPair(MsvAvFlags, []byte{0x00, 0x00, 0x00, 0x02})
	result = avPairs.Bytes()
	expected, _ = hex.DecodeString("01000c00530065007200760065007200060004000000000200000000")
	if !bytes.Equal(result, expected) {
		t.Errorf("MsvAvFlags is not correct got %s expected %s", hex.EncodeToString(result), "01000c00530065007200760065007200060004000000000200000000")
	}

}

func TestReadAvPairs(t *testing.T) {

	/* Fom http://davenport.sourceforge.net/ntlm.html#appendixC8
		Target Information block:
	    02000c00    NetBIOS Domain Name (length 12)
	    54004500530054004e005400    "TESTNT"
	    01000c00    NetBIOS Server Name (length 12)
	    4d0045004d00420045005200    "MEMBER"
	    03001e00    DNS Server Name (length 30)
	    6d0065006d006200650072002e0074006500730074002e0063006f006d00
	        "member.test.com"
	    00000000    Target Information Terminator
	*/
	avBytes, _ := hex.DecodeString("02000c0054004500530054004e00540001000c004d0045004d0042004500520003001e006d0065006d006200650072002e0074006500730074002e0063006f006d0000000000")
	avPairs := ReadAvPairs(avBytes)

	// Check three elements only
	if avPairs == nil || len(avPairs.List) != 3 {
		t.Errorf("AvPairs not read correctly")
	}

	// Test MsvAvNbComputerName
	if avPair := avPairs.Find(MsvAvNbComputerName); avPair == nil {
		t.Errorf("MsvAvNbComputerName not found in AvPair list")
	} else {
		result := avPair.UnicodeStringValue()
		expected := "MEMBER"
		if result != expected {
			t.Errorf("MsvAvNbComputerName is not correct got %s expected %s", result, "expected")
		}
	}

	// Test MsvAvNbDomainName
	if avPair := avPairs.Find(MsvAvNbDomainName); avPair == nil {
		t.Errorf("MsvAvNbDomainName not found in AvPair list")
	} else {
		result := avPair.UnicodeStringValue()
		expected := "TESTNT"
		if result != expected {
			t.Errorf("MsvAvNbDomainName is not correct got %s expected %s", result, "expected")
		}
	}

	// Test MsvAvDnsComputerName
	if avPair := avPairs.Find(MsvAvDnsComputerName); avPair == nil {
		t.Errorf("MsvAvDnsComputerName not found in AvPair list")
	} else {
		result := avPair.UnicodeStringValue()
		expected := "member.test.com"
		if result != expected {
			t.Errorf("MsvAvDnsComputerName is not correct got %s expected %s", result, "expected")
		}
	}

	// Convert back to byte array and check equivalence
	if !bytes.Equal(avPairs.Bytes(), avBytes) {
		t.Errorf("Encoding AvPairs to []byte produced different encoding. Got %x, expected %x", avPairs.Bytes(), avBytes)
	}
}

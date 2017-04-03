package ntlm

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestDecodeNegotiateNoDomainNoWorkstation(t *testing.T) {
	negotiateMessage := "TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAGA4AlAAAADw=="
	negotiateData, err := base64.StdEncoding.DecodeString(negotiateMessage)

	if err != nil {
		t.Error("Could not base64 decode message data")
	}

	negotiate, err := ParseNegotiateMessage(negotiateData)

	if err != nil || negotiate == nil {
		t.Error("Failed to parse negotiate message " + err.Error())
	}

	if negotiate.NegotiateFlags != uint32(0xE20882B7) {
		t.Errorf("negotiate negotiate flags not correct should be %v got %d", uint32(0xE20882B7), negotiate.NegotiateFlags)
	}

	// NTLM specification says offset should be set to the offset from the beginning of the message to where the field would start if it was present
	// However http://davenport.sourceforge.net/ntlm.html suggests that a zero offset is also value. Test case accepts either
	if negotiate.DomainNameFields.Len != 0 || negotiate.DomainNameFields.MaxLen != 0 || !(negotiate.DomainNameFields.Offset == 0 || negotiate.DomainNameFields.Offset == 40) {
		values := fmt.Sprintf("DomainNameFields Len:%v MaxLen:%v Offset:%v", negotiate.DomainNameFields.Len, negotiate.DomainNameFields.MaxLen, negotiate.DomainNameFields.Offset)
		t.Error("Failed to parse Domain Name in negotiate: " + values)
	}

	// NTLM specification says offset should be set to the offset from the beginning of the message to where the field would start if it was present
	// However http://davenport.sourceforge.net/ntlm.html suggests that a zero offset is also value. Test case accepts either
	if negotiate.WorkstationFields.Len != 0 || negotiate.WorkstationFields.MaxLen != 0 || !(negotiate.WorkstationFields.Offset == 0 || negotiate.WorkstationFields.Offset == 40) {
		values := fmt.Sprintf("WorkstationFields Len:%v MaxLen:%v Offset:%v", negotiate.WorkstationFields.Len, negotiate.WorkstationFields.MaxLen, negotiate.WorkstationFields.Offset)
		t.Error("Failed to parse Workstation Name in negotiate: " + values)
	}

	if negotiate.Version.ProductMajorVersion != 6 || negotiate.Version.ProductMinorVersion != 3 || negotiate.Version.ProductBuild != 9600 || negotiate.Version.NTLMRevisionCurrent != 15 {
		t.Error("Version information is not correct: '" + negotiate.Version.String() + "'")
	}

	if len(negotiate.Payload) != 0 {
		t.Error("Payload length is not long enough")
	}

	negotiate.String()

	outBytes := negotiate.Bytes()

	if len(outBytes) > 0 {
		reparsed, err := ParseNegotiateMessage(outBytes)
		if err != nil {
			t.Error("Could not re-parse negotiate message")
		}
		if reparsed.String() != negotiate.String() {
			t.Error("Reparsed message is not the same")
		}
	} else {
		t.Error("Invalid negotiate messsage bytes")
	}
}

func TestDecodeNegotiate(t *testing.T) {
	negotiateMessage := "TlRMTVNTUAABAAAABzIAAgYABgAzAAAACwALACgAAAAFAJMIAAAAD1dPUktTVEFUSU9ORE9NQUlO"
	negotiateData, err := base64.StdEncoding.DecodeString(negotiateMessage)

	if err != nil {
		t.Error("Could not base64 decode message data")
	}

	negotiate, err := ParseNegotiateMessage(negotiateData)

	if err != nil || negotiate == nil {
		t.Error("Failed to parse negotiate message: " + err.Error())
	}

	expectedFlags := uint32(0)
	expectedFlags = NTLMSSP_NEGOTIATE_UNICODE.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_NTLM.Set(expectedFlags)
	expectedFlags = NTLMSSP_REQUEST_TARGET.Set(expectedFlags)
	expectedFlags = NTLM_NEGOTIATE_OEM.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_VERSION.Set(expectedFlags)

	if negotiate.NegotiateFlags != expectedFlags {
		t.Errorf("negotiate negotiate flags not correct should be %v got %d", expectedFlags, negotiate.NegotiateFlags)
	}

	if negotiate.DomainNameFields.Len != uint16(len("DOMAIN")) && negotiate.DomainNameFields.String() != "DOMAIN" {
		t.Error("Domain name fields is not correct: '" + negotiate.DomainNameFields.String() + "'")
	}

	if negotiate.WorkstationFields.Len != uint16(len("WORKSTATION")) && negotiate.DomainNameFields.String() != "WORKSTATION" {
		t.Error("Workstation name fields is not correct: '" + negotiate.WorkstationFields.String() + "'")
	}

	if negotiate.Version.ProductMajorVersion != 5 || negotiate.Version.ProductMinorVersion != 0 || negotiate.Version.ProductBuild != 2195 || negotiate.Version.NTLMRevisionCurrent != 15 {
		t.Error("Version information is not correct: '" + negotiate.Version.String() + "'")
	}

	if len(negotiate.Payload) != int(negotiate.DomainNameFields.Len+negotiate.WorkstationFields.Len) {
		t.Error("Payload length is not long enough")
	}

	negotiate.String()

	outBytes := negotiate.Bytes()

	if len(outBytes) > 0 {
		reparsed, err := ParseNegotiateMessage(outBytes)
		if err != nil {
			t.Error("Could not re-parse negotiate message")
		}
		if reparsed.String() != negotiate.String() {
			t.Error("Reparsed message is not the same")
		}
	} else {
		t.Error("Invalid negotiate messsage bytes")
	}
}

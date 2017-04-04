//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestDecodeChallenge(t *testing.T) {
	challengeMessage := "TlRMTVNTUAACAAAAAAAAADgAAADzgpjiuaopAbx9ejQAAAAAAAAAAKIAogA4AAAABQLODgAAAA8CAA4AUgBFAFUAVABFAFIAUwABABwAVQBLAEIAUAAtAEMAQgBUAFIATQBGAEUAMAA2AAQAFgBSAGUAdQB0AGUAcgBzAC4AbgBlAHQAAwA0AHUAawBiAHAALQBjAGIAdAByAG0AZgBlADAANgAuAFIAZQB1AHQAZQByAHMALgBuAGUAdAAFABYAUgBlAHUAdABlAHIAcwAuAG4AZQB0AAAAAAA="
	challengeData, err := base64.StdEncoding.DecodeString(challengeMessage)

	if err != nil {
		t.Error("Could not base64 decode message data")
	}

	challenge, err := ParseChallengeMessage(challengeData)

	if err != nil || challenge == nil {
		t.Error("Failed to parse challenge message " + err.Error())
	}

	if challenge.TargetName != nil && challenge.TargetName.Len > 0 {
		values := fmt.Sprintf("TargetName Len:%v MaxLen:%v Offset:%v", challenge.TargetName.Len, challenge.TargetName.MaxLen, challenge.TargetName.Offset)
		t.Error("Failed to parse Target Name in challenge: " + values)
	}

	if challenge.NegotiateFlags != uint32(3801645811) {
		t.Errorf("Challenge negotiate flags not correct should be %v got %d", uint32(3801645811), challenge.NegotiateFlags)
	}

	serverChallenge, err := hex.DecodeString("B9AA2901BC7D7A34")
	if !bytes.Equal(challenge.ServerChallenge, serverChallenge) {
		hex := hex.EncodeToString(challenge.ServerChallenge)
		t.Error("Server challenge is not correct '" + hex + "'")
	}

	if challenge.Version.ProductMajorVersion != 5 || challenge.Version.ProductMinorVersion != 2 || challenge.Version.ProductBuild != 3790 || challenge.Version.NTLMRevisionCurrent != 15 {
		t.Error("Version information is not correct: '" + challenge.Version.String() + "'")
	}

	if len(challenge.Payload) != int(challenge.TargetInfoPayloadStruct.Len) {
		t.Error("Payload length is not long enough")
	}

	challenge.String()

	outBytes := challenge.Bytes()

	if len(outBytes) > 0 {
		reparsed, err := ParseChallengeMessage(outBytes)
		if err != nil {
			t.Error("Could not re-parse challenge message")
		}
		if reparsed.String() != challenge.String() {
			t.Error("Reparsed message is not the same")
		}
	} else {
		t.Error("Invalid challenge messsage bytes")
	}
}

func TestDecodeChallengeWithSealing(t *testing.T) {
	challengeMessage := "TlRMTVNTUAACAAAADAAMADgAAAA1goriE1O8+WkjYuQAAAAAAAAAAFAAUABEAAAABgOAJQAAAA9UAEUAUwBUAE4AVAACAAwAVABFAFMAVABOAFQAAQAMAFQARQBTAFQATgBUAAQADABUAEUAUwBUAE4AVAADAAwAVABFAFMAVABOAFQABwAIADOtQjcPdtIBAAAAAA=="
	challengeData, err := base64.StdEncoding.DecodeString(challengeMessage)

	if err != nil {
		t.Error("Could not base64 decode message data")
	}

	challenge, err := ParseChallengeMessage(challengeData)

	if err != nil || challenge == nil {
		t.Error("Failed to parse challenge message " + err.Error())
	}

	if challenge.TargetName.Len != uint16(len("TESTNT")) && challenge.TargetName.String() != "TESTNT" {
		t.Error("Target name fields is not correct: '" + challenge.TargetName.String() + "'")
	}

	expectedFlags := uint32(0)
	expectedFlags = NTLMSSP_NEGOTIATE_56.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_128.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_VERSION.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_TARGET_INFO.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(expectedFlags)
	expectedFlags = NTLMSSP_TARGET_TYPE_SERVER.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_NTLM.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_SEAL.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_SIGN.Set(expectedFlags)
	expectedFlags = NTLMSSP_REQUEST_TARGET.Set(expectedFlags)
	expectedFlags = NTLMSSP_NEGOTIATE_UNICODE.Set(expectedFlags)

	if challenge.NegotiateFlags != expectedFlags {
		t.Errorf("Challenge negotiate flags not correct should be %v got %d", expectedFlags, challenge.NegotiateFlags)
	}

	serverChallenge, err := hex.DecodeString("1353bcf9692362e4")
	if !bytes.Equal(challenge.ServerChallenge, serverChallenge) {
		hex := hex.EncodeToString(challenge.ServerChallenge)
		t.Error("Server challenge is not correct '" + hex + "'")
	}

	if challenge.Version.ProductMajorVersion != 6 || challenge.Version.ProductMinorVersion != 3 || challenge.Version.ProductBuild != 9600 || challenge.Version.NTLMRevisionCurrent != 15 {
		t.Error("Version information is not correct: '" + challenge.Version.String() + "'")
	}

	if len(challenge.Payload) != int(challenge.TargetName.Len+challenge.TargetInfoPayloadStruct.Len) {
		t.Error("Payload length is not long enough")
	}

	challenge.String()

	outBytes := challenge.Bytes()

	if len(outBytes) > 0 {
		reparsed, err := ParseChallengeMessage(outBytes)
		if err != nil {
			t.Error("Could not re-parse challenge message")
		}
		if reparsed.String() != challenge.String() {
			t.Error("Reparsed message is not the same")
		}
	} else {
		t.Error("Invalid challenge messsage bytes")
	}
}

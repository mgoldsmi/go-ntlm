//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func checkV2Value(t *testing.T, name string, value []byte, expected string, err error) {
	if err != nil {
		t.Errorf("NTLMv2 %s received error: %s", name, err)
	} else {
		expectedBytes, _ := hex.DecodeString(expected)
		if !bytes.Equal(expectedBytes, value) {
			t.Errorf("NTLMv2 %s is not correct got %s expected %s", name, hex.EncodeToString(value), expected)
		}
	}
}

func TestNTOWFv2(t *testing.T) {
	result := ntowfv2("User", "Password", "Domain")
	// Sample value from 4.2.4.1.1 in MS-NLMP
	expected, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if !bytes.Equal(result, expected) {
		t.Errorf("NTOWFv2 is not correct got %s expected %s", hex.EncodeToString(result), "0c868a403bfd7a93a3001ef22ef02e3f")
	}
}

func TestNTLMv2(t *testing.T) {
	flags := uint32(0)
	flags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	flags = NTLMSSP_NEGOTIATE_56.Set(flags)
	flags = NTLMSSP_NEGOTIATE_128.Set(flags)
	flags = NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	flags = NTLMSSP_NEGOTIATE_TARGET_INFO.Set(flags)
	flags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	flags = NTLMSSP_TARGET_TYPE_SERVER.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = NTLM_NEGOTIATE_OEM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)

	//	n := new(V2Session)
	//	n.SetUserInfo("User","Password","Domain")
	//	n.NegotiateFlags = flags
	//	n.responseKeyNT, _ = hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	//	n.responseKeyLM = n.responseKeyNT
	//	n.clientChallenge, _ = hex.DecodeString("aaaaaaaaaaaaaaaa")
	//	n.serverChallenge, _ = hex.DecodeString("0123456789abcdef")

	// Encrypted Random Session key
	//c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e

	// Challenge message
	client := new(V2ClientSession)
	client.SetConfigFlags(flags)
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("SQUAREMILL")

	challengeMessageBytes, _ := hex.DecodeString("4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef00000000000000002400240044000000060070170000000f53006500720076006500720002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	challengeMessage, err := ParseChallengeMessage(challengeMessageBytes)
	if err == nil {
		challengeMessage.String()
	} else {
		t.Errorf("Could not parse challenge message: %s", err)
	}

	err = client.ProcessChallengeMessage(challengeMessage)
	if err != nil {
		t.Errorf("Could not process challenge message: %s", err)
	}

	server := new(V2ServerSession)
	server.SetUserInfo("User", "Password", "Domain")
	server.SetTargetInfo(true, "UKBP-CBTRMFE06", "REUTERS", "ukbp-cbtrmfe06.Reuters.net", "Reuters.net", "Reuters.net")
	server.serverChallenge = challengeMessage.ServerChallenge

	// Authenticate message
	r := strings.NewReplacer("\n", "", "\t", "", " ", "")
	authenticateMessageBytes, _ := hex.DecodeString(r.Replace(`
		4e544c4d535350000300000018001800
		6c00000054005400840000000c000c00
		48000000080008005400000010001000
		5c00000010001000d8000000358288e2
		0501280a0000000f44006f006d006100
		69006e00550073006500720043004f00
		4d005000550054004500520086c35097
		ac9cec102554764a57cccc19aaaaaaaa
		aaaaaaaa68cd0ab851e51c96aabc927b
		ebef6a1c010100000000000000000000
		00000000aaaaaaaaaaaaaaaa00000000
		02000c0044006f006d00610069006e00
		01000c00530065007200760065007200
		0000000000000000c5dad2544fc97990
		94ce1ce90bc9d03e`))

	authenticateMessage, err := ParseAuthenticateMessage(authenticateMessageBytes, 2)
	if err == nil {
		authenticateMessage.String()
	} else {
		t.Errorf("Could not parse authenticate message: %s", err)
	}

	err = server.ProcessAuthenticateMessage(authenticateMessage)
	if err != nil {
		t.Errorf("Could not process authenticate message: %s", err)
	}

	checkV2Value(t, "SessionBaseKey", server.sessionBaseKey, "8de40ccadbc14a82f15cb0ad0de95ca3", nil)
	checkV2Value(t, "NTChallengeResponse", server.ntChallengeResponse[0:16], "68cd0ab851e51c96aabc927bebef6a1c", nil)
	checkV2Value(t, "LMChallengeResponse", server.lmChallengeResponse, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa", nil)

	checkV2Value(t, "client seal key", server.ClientSealingKey, "59f600973cc4960a25480a7c196e4c58", nil)
	checkV2Value(t, "client signing key", server.ClientSigningKey, "4788dc861b4782f35d43fd98fe1a2d39", nil)
}

func NTLMv2SessionNegotiation(t *testing.T, client *ClientSession, server *ServerSession, mode Mode) (err error) {

	c, s := *client, *server

	if mode.Stream {
		nm, err := c.GenerateNegotiateMessage()
		if err != nil {
			err := fmt.Errorf("Could not generate negotiate message: %s", err)
			return err
		}

		nm, err = ParseNegotiateMessage(nm.Bytes())
		if err != nil {
			err := fmt.Errorf("Error encoding/decoding negotiate message: %s", err)
			return err
		}

		err = s.ProcessNegotiateMessage(nm)
		if err != nil {
			err := fmt.Errorf("Could not process negotiate message: %s", err)
			return err
		}
	}

	cm, err := s.GenerateChallengeMessage()
	if err != nil {
		err := fmt.Errorf("Could not generate challenge message: %s", err)
		return err
	}

	//fmt.Printf("Challenge message: %v", cm)

	cm, err = ParseChallengeMessage(cm.Bytes())
	if err != nil {
		err := fmt.Errorf("Error encoding/decoding challenge message: %s", err)
		return err
	}

	err = c.ProcessChallengeMessage(cm)
	if err != nil {
		err := fmt.Errorf("Could not process challenge message: %s", err)
		return err
	}

	am, err := c.GenerateAuthenticateMessage()
	if err != nil {
		err := fmt.Errorf("Could not generate authenticate message: %s", err)
		return err
	}

	//fmt.Printf("Authenticate message: %v", am)

	am, err = ParseAuthenticateMessage(am.Bytes(), 2)
	if err != nil {
		err := fmt.Errorf("Error encoding/decoding authentication message: %s", err)
		return err
	}

	err = s.ProcessAuthenticateMessage(am)
	if err != nil {
		err := fmt.Errorf("Failed to authenticate session authenticate message: %s", err)
		return err
	}

	// t.Log("Successful authentication\n")
	return nil
}

/**
* Test NTLMv2 connection-oriented client & server session negotiation with signing and version exchange
 */
func TestNTLMv2ConnectionOriented(t *testing.T) {

	mode := ConnectionOrientedMode
	client, err := CreateClientSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}

	if ver, err := GetVersion("Windows 7 SP1"); err != nil {
		t.Errorf("Could not get version for Windows 7 SP1: %s", err)
		t.Fail()
	} else {
		client.SetVersion(ver)
	}

	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	server, err := CreateServerSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create server session: %s", err)
		t.FailNow()
	}

	if ver, err := GetVersion("Windows Server 2012 R2"); err != nil {
		t.Errorf("Could not get version for Windows Server 2012 R2: %s", err)
		t.Fail()
	} else {
		server.SetVersion(ver)
	}

	server.SetUserInfo("User", "Password", "Domain")
	server.SetTargetInfo(false, "UKBP-CBTRMFE06", "REUTERS", "ukbp-cbtrmfe06.Reuters.net", "Reuters.net", "Reuters.net")

	// Attempt session negotiation
	if err := NTLMv2SessionNegotiation(t, &client, &server, mode); err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Now check if client and server session states are equivalent by signing and sealing messages
	// We use the ntlm library end to end to make sure that Mac, VerifyMac
	// the client should be able to verify the server's mac
	sig := "<NTLM><foo><bar>"
	if mac, err := server.Mac([]byte(sig), 100); err != nil {
		t.Errorf("Could not generate a mac for %s", sig)
		t.Fail()
	} else {
		if matches, err := client.VerifyMac([]byte(sig), mac, 100); err != nil {
			t.Errorf("Could not verify mac for %s (mac = %v)", sig, mac)
			t.Fail()
		} else if !matches {
			t.Errorf("Server's Mac couldn't be verified by client")
			t.Fail()
		}
	}

	if mac, err := client.Mac([]byte(sig), 100); err != nil {
		t.Errorf("Could not generate a mac for %s", sig)
		t.Fail()
	} else {
		if matches, err := server.VerifyMac([]byte(sig), mac, 100); err != nil {
			t.Errorf("Could not verify mac for %s (mac = %v)", sig, mac)
			t.Fail()
		} else if !matches {
			t.Errorf("Client's Mac couldn't be verified by server")
			t.Fail()
		}
	}
}

/**
* Test NTLMv2 connectionless client & server session negotiation (no version exchange) with signing and sealing
 */
func TestNTLMv2Connectionless(t *testing.T) {

	mode := Mode{Integrity: true, Confidentiality: true, Stream: false}
	client, err := CreateClientSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	server, err := CreateServerSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create server session: %s", err)
		t.FailNow()
	}

	server.SetUserInfo("User", "Password", "Domain")
	server.SetTargetInfo(false, "UKBP-CBTRMFE06", "REUTERS", "ukbp-cbtrmfe06.Reuters.net", "Reuters.net", "Reuters.net")

	// Attempt session negotiation
	if err := NTLMv2SessionNegotiation(t, &client, &server, mode); err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Now check if client and server session states are equivalent by signing and sealing messages
	// We use the ntlm library end to end to make sure that Mac, VerifyMac
	// the client should be able to verify the server's mac
	sig := "<NTLM><foo><bar>"
	if mac, err := server.Mac([]byte(sig), 100); err != nil {
		t.Errorf("Could not generate a mac for %s", sig)
		t.Fail()
	} else {
		if matches, err := client.VerifyMac([]byte(sig), mac, 100); err != nil {
			t.Errorf("Could not verify mac for %s (mac = %v)", sig, mac)
			t.Fail()
		} else if !matches {
			t.Errorf("Server's Mac couldn't be verified by client")
			t.Fail()
		}
	}

	if mac, err := client.Mac([]byte(sig), 100); err != nil {
		t.Errorf("Could not generate a mac for %s", sig)
		t.Fail()
	} else {
		if matches, err := server.VerifyMac([]byte(sig), mac, 100); err != nil {
			t.Errorf("Could not verify mac for %s (mac = %v)", sig, mac)
			t.Fail()
		} else if !matches {
			t.Errorf("Client's Mac couldn't be verified by server")
			t.Fail()
		}
	}

	// Check sealing
	message := "Confirm encryption of this message"
	if sealed, mac, err := client.Wrap([]byte(message), 20); err != nil {
		t.Errorf("Client unable to seal message %s", err)
		t.Fail()
	} else {
		if unsealed, ok, err := server.Unwrap([]byte(sealed), mac, 20); err != nil {
			t.Errorf("Failed to unseal message %s", err)
			t.Logf("Signature was: %v", mac)
			t.Fail()
		} else if !ok {
			t.Error("Expected MAC did not match")
			t.Fail()
		} else if bytes.Compare([]byte(message), unsealed) != 0 {
			t.Error("Unencrypted message does not match original message")
			t.Fail()
		}
	}
}

func TestNTLMv2FailedAuthentication(t *testing.T) {

	// Create client session without signing and sealing
	mode := ConnectionOrientedMode
	client, err := CreateClientSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	server, err := CreateServerSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create server session: %s", err)
		t.FailNow()
	}
	server.SetUserInfo("User", "password", "Domain")
	server.SetTargetInfo(false, "UKBP-CBTRMFE06", "REUTERS", "ukbp-cbtrmfe06.Reuters.net", "Reuters.net", "Reuters.net")

	// Attempt session negotiation
	if err := NTLMv2SessionNegotiation(t, &client, &server, mode); err == nil {
		t.Error("Session negotiation was successful despite wrong password")
		t.Fail()
	}
}

func TestNTLMv2ClientAuthPolicy(t *testing.T) {

	// Create client session without signing and sealing
	mode := ConnectionOrientedMode
	client, err := CreateClientSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	server, err := CreateServerSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create server session: %s", err)
		t.FailNow()
	}
	server.SetUserInfo("User", "Password", "Domain")
	server.SetTargetInfo(false, "UKBP-CBTRMFE06", "REUTERS", "ukbp-cbtrmfe06.Reuters.net", "Reuters.net", "Reuters.net")

	// Set min auth policy that requires signing and sealing
	minAuthPolicy := uint32(0)
	minAuthPolicy = NTLMSSP_NEGOTIATE_128.Set(minAuthPolicy)
	minAuthPolicy = NTLMSSP_NEGOTIATE_SEAL.Set(minAuthPolicy)
	minAuthPolicy = NTLMSSP_NEGOTIATE_SIGN.Set(minAuthPolicy)
	client.SetMinAuthPolicy(minAuthPolicy)

	// Attempt session negotiation
	if err := NTLMv2SessionNegotiation(t, &client, &server, mode); err == nil {
		t.Error("Session negotiation was successful despite not meeting minimum authentication policy")
		t.Fail()
	}
}

func TestNTLMv2ServerAuthPolicy(t *testing.T) {

	// Create client session without signing and sealing
	mode := ConnectionOrientedMode
	client, err := CreateClientSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	server, err := CreateServerSession(Version2, mode)
	if err != nil {
		t.Errorf("Could not create server session: %s", err)
		t.FailNow()
	}
	server.SetUserInfo("User", "Password", "Domain")
	server.SetTargetInfo(false, "UKBP-CBTRMFE06", "REUTERS", "ukbp-cbtrmfe06.Reuters.net", "Reuters.net", "Reuters.net")

	// Set min auth policy that requires signing and sealing
	minAuthPolicy := uint32(0)
	minAuthPolicy = NTLMSSP_NEGOTIATE_128.Set(minAuthPolicy)
	minAuthPolicy = NTLMSSP_NEGOTIATE_SEAL.Set(minAuthPolicy)
	minAuthPolicy = NTLMSSP_NEGOTIATE_SIGN.Set(minAuthPolicy)
	server.SetMinAuthPolicy(minAuthPolicy)

	// Attempt session negotiation
	if err := NTLMv2SessionNegotiation(t, &client, &server, mode); err == nil {
		t.Error("Session negotiation was successful despite not meeting minimum authentication policy")
		t.Fail()
	}
}

func TestNTLMv2WithDomain(t *testing.T) {
	authenticateMessage := "TlRMTVNTUAADAAAAGAAYALYAAADSANIAzgAAADQANABIAAAAIAAgAHwAAAAaABoAnAAAABAAEACgAQAAVYKQQgUCzg4AAAAPYQByAHIAYQB5ADEAMgAuAG0AcwBnAHQAcwB0AC4AcgBlAHUAdABlAHIAcwAuAGMAbwBtAHUAcwBlAHIAcwB0AHIAZQBzAHMAMQAwADAAMAAwADgATgBZAEMAVgBBADEAMgBTADIAQwBNAFMAQQBPYrLjU4h0YlWZeEoNvTJtBQMnnJuAeUwsP+vGmAHNRBpgZ+4ChQLqAQEAAAAAAACPFEIFjx7OAQUDJ5ybgHlMAAAAAAIADgBSAEUAVQBUAEUAUgBTAAEAHABVAEsAQgBQAC0AQwBCAFQAUgBNAEYARQAwADYABAAWAFIAZQB1AHQAZQByAHMALgBuAGUAdAADADQAdQBrAGIAcAAtAGMAYgB0AHIAbQBmAGUAMAA2AC4AUgBlAHUAdABlAHIAcwAuAG4AZQB0AAUAFgBSAGUAdQB0AGUAcgBzAC4AbgBlAHQAAAAAAAAAAAANuvnqD3K88ZpjkLleL0NW"

	server := new(V2ServerSession)
	server.SetUserInfo("blahblah", "Welcome1", "blahblah")

	authenticateData, _ := base64.StdEncoding.DecodeString(authenticateMessage)
	a, _ := ParseAuthenticateMessage(authenticateData, 2)

	serverChallenge, _ := hex.DecodeString("3d74b2d04ebe1eb3")
	server.SetServerChallenge(serverChallenge)

	err := server.ProcessAuthenticateMessage(a)
	if err != nil {
		t.Error("Could not process authenticate message: %s\n", err)
	}
}

func TestWindowsTimeConversion(t *testing.T) {
	// From http://davenport.sourceforge.net/ntlm.html#theType3Message
	// Next, the blob is constructed. The timestamp is the most tedious part of this; looking at the clock on my desk,
	// it's about 6:00 AM EDT on June 17th, 2003. In Unix time, that would be 1055844000 seconds after the Epoch.
	// Adding 11644473600 will give us seconds after January 1, 1601 (12700317600). Multiplying by 107 (10000000)
	// will give us tenths of a microsecond (127003176000000000). As a little-endian 64-bit value, this is
	// "0x0090d336b734c301" (in hexadecimal).
	unix := time.Unix(1055844000, 0)
	result := timeToWindowsFileTime(unix)
	checkV2Value(t, "Timestamp", result, "0090d336b734c301", nil)
}

func TestNTLMv2ClientAuthentication(t *testing.T) {
	client := new(V2ClientSession)

	// From the NTLM specification
	flags := uint32(0)
	flags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	flags = NTLMSSP_NEGOTIATE_56.Set(flags)
	flags = NTLMSSP_NEGOTIATE_128.Set(flags)
	flags = NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	flags = NTLMSSP_NEGOTIATE_TARGET_INFO.Set(flags)
	flags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	flags = NTLMSSP_TARGET_TYPE_SERVER.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = NTLM_NEGOTIATE_OEM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)
	client.SetConfigFlags(flags)
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	bytes, _ := hex.DecodeString("4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef00000000000000002400240044000000060070170000000f53006500720076006500720002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	if cm, err := ParseChallengeMessage(bytes); err != nil {
		t.Errorf("Could not parse challenge message: %s", err)
		t.FailNow()
	} else {
		if err := client.ProcessChallengeMessage(cm); err != nil {
			t.Errorf("Could not parse challenge message: %s", err)
			t.FailNow()
		}
	}

	// Override these random values to allow calculations to be checked
	client.clientChallenge, _ = hex.DecodeString("aaaaaaaaaaaaaaaa")
	client.exportedSessionKey, _ = hex.DecodeString("55555555555555555555555555555555")
	client.timestamp = make([]byte, 8)

	if _, err := client.GenerateAuthenticateMessage(); err != nil {
		t.Errorf("Error generating authenticate message: %s", err)
		t.FailNow()
	}

	checkV2Value(t, "NTChallengeResponse", client.ntChallengeResponse[0:16], "68cd0ab851e51c96aabc927bebef6a1c", nil)
	checkV2Value(t, "LMChallengeResponse", client.lmChallengeResponse, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa", nil)
	checkV2Value(t, "SessionBaseKey", client.sessionBaseKey, "8de40ccadbc14a82f15cb0ad0de95ca3", nil)
	checkV2Value(t, "EncryptedRandomSessionKey", client.encryptedRandomSessionKey, "c5dad2544fc9799094ce1ce90bc9d03e", nil)
	checkV2Value(t, "client seal key", client.ClientSealingKey, "59f600973cc4960a25480a7c196e4c58", nil)
	checkV2Value(t, "client signing key", client.ClientSigningKey, "4788dc861b4782f35d43fd98fe1a2d39", nil)

	// Check wrap algorithm
	encmessage, mac, err := client.Wrap(utf16FromString("Plaintext"), 0)
	if err != nil {
		t.Errorf("Error generating authenticate message: %s", err)
		t.FailNow()
	}

	checkV2Value(t, "Encrypted message", encmessage, "54e50165bf1936dc996020c1811b0f06fb5f", nil)
	checkV2Value(t, "MAC", mac, "010000007fb38ec5c55d497600000000", nil)
}

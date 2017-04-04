//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestLMOWFv1(t *testing.T) {
	// Sample from MS-NLMP
	result, err := lmowfv1("Password")
	expected, _ := hex.DecodeString("e52cac67419a9a224a3b108f3fa6cb6d")
	if err != nil || !bytes.Equal(result, expected) {
		t.Errorf("LMNOWFv1 is not correct, got %s expected %s", hex.EncodeToString(result), "e52cac67419a9a224a3b108f3fa6cb6d")
	}
}

func TestNTOWFv1(t *testing.T) {
	// Sample from MS-NLMP
	result := ntowfv1("Password")
	expected, _ := hex.DecodeString("a4f49c406510bdcab6824ee7c30fd852")
	if !bytes.Equal(result, expected) {
		t.Error("NTOWFv1 is not correct")
	}
}

func checkV1Value(t *testing.T, name string, value []byte, expected string, err error) {
	if err != nil {
		t.Errorf("NTLMv1 %s received error: %s", name, err)
	} else {
		expectedBytes, _ := hex.DecodeString(expected)
		if !bytes.Equal(expectedBytes, value) {
			t.Errorf("NTLMv1 %s is not correct got %s expected %s", name, hex.EncodeToString(value), expected)
		}
	}
}

// There was an issue where all NTLMv1 authentications with extended session security
// would authenticate. This was due to a bug in the MS-NLMP docs. This tests for that issue
func TestNtlmV1ExtendedSessionSecurity(t *testing.T) {
	// NTLMv1 with extended session security
	challengeMessage := "TlRMTVNTUAACAAAAAAAAADgAAABRgphiRy3oSZvn1I4AAAAAAAAAAKIAogA4AAAABQEoCgAAAA8CAA4AUgBFAFUAVABFAFIAUwABABwAVQBLAEIAUAAtAEMAQgBUAFIATQBGAEUAMAA2AAQAFgBSAGUAdQB0AGUAcgBzAC4AbgBlAHQAAwA0AHUAawBiAHAALQBjAGIAdAByAG0AZgBlADAANgAuAFIAZQB1AHQAZQByAHMALgBuAGUAdAAFABYAUgBlAHUAdABlAHIAcwAuAG4AZQB0AAAAAAA="
	authenticateMessage := "TlRMTVNTUAADAAAAGAAYAJgAAAAYABgAsAAAAAAAAABIAAAAOgA6AEgAAAAWABYAggAAABAAEADIAAAAVYKYYgUCzg4AAAAPMQAwADAAMAAwADEALgB3AGMAcABAAHQAaABvAG0AcwBvAG4AcgBlAHUAdABlAHIAcwAuAGMAbwBtAE4AWQBDAFMATQBTAEcAOQA5ADAAOQBRWAK3h/TIywAAAAAAAAAAAAAAAAAAAAA3tp89kZU1hs1XZp7KTyGm3XsFAT9stEDW9YXDaeYVBmBcBb//2FOu"

	challengeData, _ := base64.StdEncoding.DecodeString(challengeMessage)
	c, err := ParseChallengeMessage(challengeData)
	if err != nil {
		t.Errorf("Could not process challenge message: %s", err)
	}

	authenticateData, _ := base64.StdEncoding.DecodeString(authenticateMessage)
	msg, err := ParseAuthenticateMessage(authenticateData, 1)
	if err != nil {
		t.Errorf("Could not process authenticate message: %s", err)
	}

	context, err := CreateServerSession(Version1, ConnectionlessMode)
	if err != nil {
		t.Errorf("Could not create NTLMv1 session")
	}
	context.SetUserInfo("100001.wcp.thomsonreuters.com", "notmypass", "")
	context.SetServerChallenge(c.ServerChallenge)
	err = context.ProcessAuthenticateMessage(msg)
	if err == nil {
		t.Errorf("This message should have failed to authenticate, but it passed", err)
	}
}

func TestNtlmV1(t *testing.T) {
	flags := uint32(0)
	flags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	flags = NTLMSSP_NEGOTIATE_56.Set(flags)
	flags = NTLMSSP_NEGOTIATE_128.Set(flags)
	flags = NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	flags = NTLMSSP_REQUEST_TARGET.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = NTLM_NEGOTIATE_OEM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)

	server := new(V1ServerSession)
	server.SetUserInfo("User", "Password", "Domain")
	server.SetTargetInfo(false, "Server", "", "", "", "")
	ver, _ := GetVersion("Windows Vista")
	server.SetVersion(ver)
	server.configFlags = flags
	server.NegotiateFlags = flags
	server.serverChallenge, _ = hex.DecodeString("0123456789abcdef")
	server.exportedSessionKey, _ = hex.DecodeString("55555555555555555555555555555555")

	var err error

	// 4.2.2.1.1 LMOWFv1
	err = server.fetchResponseKeys()
	checkV1Value(t, "ResponseKeyLM", server.responseKeyLM, "e52cac67419a9a224a3b108f3fa6cb6d", err)

	// 4.2.2.1.2 NTOWFv1
	checkV1Value(t, "ResponseKeyNT", server.responseKeyNT, "a4f49c406510bdcab6824ee7c30fd852", err)

	// 4.2.2.1.3 Session Base Key and Key Exchange Key
	err = server.computeExpectedResponses()
	checkV1Value(t, "sessionBaseKey", server.sessionBaseKey, "d87262b0cde4b1cb7499becccdf10784", err)

	// 4.2.2.2.1 NTLMv1 Response
	// NTChallengeResponse with With NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY not set
	checkV1Value(t, "NTChallengeResponse", server.ntChallengeResponse, "67c43011f30298a2ad35ece64f16331c44bdbed927841f94", err)

	// 4.2.2.2.2 LMv1 Response
	// The LmChallengeResponse is specified in section 3.3.1. With the NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag
	// not set and with the NoLMResponseNTLMv1 flag not set
	checkV1Value(t, "LMChallengeResponse", server.lmChallengeResponse, "98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13", err)

	err = server.computeKeyExchangeKey()
	checkV1Value(t, "keyExchangeKey", server.keyExchangeKey, "d87262b0cde4b1cb7499becccdf10784", err)

	// If the NTLMSSP_NEGOTIATE_LM_KEY flag is set then the KeyExchangeKey is:
	server.NegotiateFlags = NTLMSSP_NEGOTIATE_LM_KEY.Set(server.NegotiateFlags)
	err = server.computeKeyExchangeKey()
	checkV1Value(t, "keyExchangeKey with NTLMSSP_NEGOTIATE_LM_KEY", server.keyExchangeKey, "b09e379f7fbecb1eaf0afdcb0383c8a0", err)
	server.NegotiateFlags = NTLMSSP_NEGOTIATE_LM_KEY.Unset(server.NegotiateFlags)

	// 4.2.2.2.3 Encrypted Session Key

	// RC4 encryption of the EncryptedRandomSessionKey with the KeyExchange key
	err = server.computeKeyExchangeKey()
	server.encryptedRandomSessionKey, err = hex.DecodeString("518822b1b3f350c8958682ecbb3e3cb7")
	err = server.computeExportedSessionKey()
	checkV1Value(t, "ExportedSessionKey", server.exportedSessionKey, "55555555555555555555555555555555", err)

	// NTLMSSP_REQUEST_NON_NT_SESSION_KEY is set:
	server.NegotiateFlags = NTLMSSP_REQUEST_NON_NT_SESSION_KEY.Set(server.NegotiateFlags)
	err = server.computeKeyExchangeKey()
	server.encryptedRandomSessionKey, err = hex.DecodeString("7452ca55c225a1ca04b48fae32cf56fc")
	err = server.computeExportedSessionKey()
	checkV1Value(t, "ExportedSessionKey - NTLMSSP_REQUEST_NON_NT_SESSION_KEY", server.exportedSessionKey, "55555555555555555555555555555555", err)
	server.NegotiateFlags = NTLMSSP_REQUEST_NON_NT_SESSION_KEY.Unset(server.NegotiateFlags)

	// NTLMSSP_NEGOTIATE_LM_KEY is set:
	server.NegotiateFlags = NTLMSSP_NEGOTIATE_LM_KEY.Set(server.NegotiateFlags)
	err = server.computeKeyExchangeKey()
	server.encryptedRandomSessionKey, err = hex.DecodeString("4cd7bb57d697ef9b549f02b8f9b37864")
	err = server.computeExportedSessionKey()
	checkV1Value(t, "ExportedSessionKey - NTLMSSP_NEGOTIATE_LM_KEY", server.exportedSessionKey, "55555555555555555555555555555555", err)
	server.NegotiateFlags = NTLMSSP_NEGOTIATE_LM_KEY.Unset(server.NegotiateFlags)

	// Reset
	err = server.computeKeyExchangeKey()
	server.encryptedRandomSessionKey, err = hex.DecodeString("518822b1b3f350c8958682ecbb3e3cb7")
	err = server.computeExportedSessionKey()
	checkV1Value(t, "ExportedSessionKey", server.exportedSessionKey, "55555555555555555555555555555555", err)

	// 4.2.2.4 GSS_WrapEx Examples

	server.serverChallenge, _ = hex.DecodeString("0123456789abcdef")
	authenticateMessageBytes, _ := hex.DecodeString("4e544c4d5353500003000000180018006c00000018001800840000000c000c00480000000800080054000000100010005c000000100010009c000000358280e20501280a0000000f44006f006d00610069006e00550073006500720043004f004d005000550054004500520098def7b87f88aa5dafe2df779688a172def11c7d5ccdef1367c43011f30298a2ad35ece64f16331c44bdbed927841f94518822b1b3f350c8958682ecbb3e3cb7")
	authenticateMessage, _ := ParseAuthenticateMessage(authenticateMessageBytes, 1)

	if err = server.ProcessAuthenticateMessage(authenticateMessage); err != nil {
		t.Errorf("Could not process authenticate message: %s", err)
		t.FailNow()
	}

	// Check wrap algorithm
	encmessage, mac, err := server.Wrap(utf16FromString("Plaintext"), 0)
	if err != nil {
		t.Errorf("Error generating authenticate message: %s", err)
		t.FailNow()
	}

	checkV1Value(t, "Encrypted message", encmessage, "56fe04d861f9319af0d7238a2e3b4d457fb8", nil)
	checkV1Value(t, "MAC", mac, "010000000000000009dcd1df2e459d36", nil)
}

func TestNTLMv1WithClientChallenge(t *testing.T) {
	flags := uint32(0)
	flags = NTLMSSP_NEGOTIATE_56.Set(flags)
	flags = NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	flags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	flags = NTLMSSP_TARGET_TYPE_SERVER.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = NTLM_NEGOTIATE_OEM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)

	n := new(V1Session)
	n.NegotiateFlags = flags
	n.responseKeyNT, _ = hex.DecodeString("a4f49c406510bdcab6824ee7c30fd852")
	n.responseKeyLM, _ = hex.DecodeString("e52cac67419a9a224a3b108f3fa6cb6d")
	n.clientChallenge, _ = hex.DecodeString("aaaaaaaaaaaaaaaa")
	n.serverChallenge, _ = hex.DecodeString("0123456789abcdef")

	var err error
	// 4.2.2.1.3 Session Base Key and Key Exchange Key
	err = n.computeExpectedResponses()
	checkV1Value(t, "sessionBaseKey", n.sessionBaseKey, "d87262b0cde4b1cb7499becccdf10784", err)
	checkV1Value(t, "LMv1Response", n.lmChallengeResponse, "aaaaaaaaaaaaaaaa00000000000000000000000000000000", err)
	checkV1Value(t, "NTLMv1Response", n.ntChallengeResponse, "7537f803ae367128ca458204bde7caf81e97ed2683267232", err)
	err = n.computeKeyExchangeKey()
	checkV1Value(t, "keyExchangeKey", n.keyExchangeKey, "eb93429a8bd952f8b89c55b87f475edc", err)

	challengeMessageBytes, _ := hex.DecodeString("4e544c4d53535000020000000c000c003800000033820a820123456789abcdef00000000000000000000000000000000060070170000000f530065007200760065007200")
	challengeMessage, err := ParseChallengeMessage(challengeMessageBytes)
	if err == nil {
		challengeMessage.String()
	} else {
		t.Errorf("Could not parse challenge message: %s", err)
	}

	client := new(V1ClientSession)
	client.SetUserInfo("User", "Password", "Domain")
	err = client.ProcessChallengeMessage(challengeMessage)
	if err != nil {
		t.Errorf("Could not process challenge message: %s", err)
	}

	server := new(V1ServerSession)
	server.SetUserInfo("User", "Password", "Domain")
	server.serverChallenge = challengeMessage.ServerChallenge

	authenticateMessageBytes, _ := hex.DecodeString("4e544c4d5353500003000000180018006c00000018001800840000000c000c00480000000800080054000000100010005c000000000000009c000000358208820501280a0000000f44006f006d00610069006e00550073006500720043004f004d0050005500540045005200aaaaaaaaaaaaaaaa000000000000000000000000000000007537f803ae367128ca458204bde7caf81e97ed2683267232")
	authenticateMessage, err := ParseAuthenticateMessage(authenticateMessageBytes, 1)
	if err == nil {
		authenticateMessage.String()
	} else {
		t.Errorf("Could not parse authenticate message: %s", err)
	}

	err = server.ProcessAuthenticateMessage(authenticateMessage)
	if err != nil {
		t.Errorf("Could not process authenticate message: %s", err)
	}

	checkV1Value(t, "SealKey", server.ClientSealingKey, "04dd7f014d8504d265a25cc86a3a7c06", nil)
	checkV1Value(t, "SignKey", server.ClientSigningKey, "60e799be5c72fc92922ae8ebe961fb8d", nil)
}

func NTLMv1SessionNegotiation(t *testing.T, client *ClientSession, server *ServerSession, mode Mode) (err error) {

	c, s := *client, *server

	if mode.stream {
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

	am, err = ParseAuthenticateMessage(am.Bytes(), 1)
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
* Test NTLMv1 connection-oriented client & server session negotiation with signing and version exchange
 */
func TestNTLMv1ConnectionOriented(t *testing.T) {

	mode := Mode{integrity: true, stream: true, version: true}
	client, err := CreateClientSession(Version1, mode)
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

	server, err := CreateServerSession(Version1, mode)
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
	if err := NTLMv1SessionNegotiation(t, &client, &server, mode); err != nil {
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
* Test NTLMv1 connectionless client & server session negotiation (no version exchange) with signing and sealing
 */
func TestNTLMv1Connectionless(t *testing.T) {

	mode := Mode{integrity: true, confidentiality: true, stream: false}
	client, err := CreateClientSession(Version1, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	server, err := CreateServerSession(Version1, mode)
	if err != nil {
		t.Errorf("Could not create server session: %s", err)
		t.FailNow()
	}

	server.SetUserInfo("User", "Password", "Domain")
	server.SetTargetInfo(false, "UKBP-CBTRMFE06", "REUTERS", "ukbp-cbtrmfe06.Reuters.net", "Reuters.net", "Reuters.net")

	// Attempt session negotiation
	if err := NTLMv1SessionNegotiation(t, &client, &server, mode); err != nil {
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

func TestNTLMv1FailedAuthentication(t *testing.T) {

	// Create client session without signing and sealing
	mode := ConnectionOrientedMode
	client, err := CreateClientSession(Version1, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	server, err := CreateServerSession(Version1, mode)
	if err != nil {
		t.Errorf("Could not create server session: %s", err)
		t.FailNow()
	}
	server.SetUserInfo("User", "anotherpassword", "Domain")
	server.SetTargetInfo(false, "UKBP-CBTRMFE06", "REUTERS", "ukbp-cbtrmfe06.Reuters.net", "Reuters.net", "Reuters.net")

	// Attempt session negotiation
	if err := NTLMv1SessionNegotiation(t, &client, &server, mode); err == nil {
		t.Error("Session negotiation was successful despite wrong password")
		t.Fail()
	}
}

func TestNTLMv1ClientAuthPolicy(t *testing.T) {

	// Create client session without signing and sealing
	mode := ConnectionOrientedMode
	client, err := CreateClientSession(Version1, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	server, err := CreateServerSession(Version1, mode)
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
	if err := NTLMv1SessionNegotiation(t, &client, &server, mode); err == nil {
		t.Error("Session negotiation was successful despite not meeting minimum authentication policy")
		t.Fail()
	}
}

func TestNTLMv1ServerAuthPolicy(t *testing.T) {

	// Create client session without signing and sealing
	mode := ConnectionOrientedMode
	client, err := CreateClientSession(Version1, mode)
	if err != nil {
		t.Errorf("Could not create client session: %s", err)
		t.FailNow()
	}
	client.SetUserInfo("User", "Password", "Domain")

	server, err := CreateServerSession(Version1, mode)
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
	if err := NTLMv1SessionNegotiation(t, &client, &server, mode); err == nil {
		t.Error("Session negotiation was successful despite not meeting minimum authentication policy")
		t.Fail()
	}
}

func TestNTLMv1ClientAuthentication(t *testing.T) {
	client := new(V1ClientSession)

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
	// flags = NTLMSSP_NEGOTIATE_LM_KEY.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = NTLM_NEGOTIATE_OEM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)
	client.SetConfigFlags(flags)
	client.SetUserInfo("User", "Password", "Domain")
	client.SetMachineName("COMPUTER")

	bytes, _ := hex.DecodeString("4e544c4d53535000020000000c000c0038000000338202e20123456789abcdef00000000000000000000000000000000060070170000000f530065007200760065007200")
	if cm, err := ParseChallengeMessage(bytes); err != nil {
		t.Errorf("Could not parse challenge message: %s", err)
		t.FailNow()
	} else {
		if err := client.ProcessChallengeMessage(cm); err != nil {
			t.Errorf("Could not process challenge message: %s", err)
			t.FailNow()
		}

		t.Log(cm)
	}

	// Override these random values to allow calculations to be checked
	client.clientChallenge, _ = hex.DecodeString("aaaaaaaaaaaaaaaa")
	client.exportedSessionKey, _ = hex.DecodeString("55555555555555555555555555555555")
	client.timestamp = make([]byte, 8)

	if _, err := client.GenerateAuthenticateMessage(); err != nil {
		t.Errorf("Error generating authenticate message: %s", err)
		t.FailNow()
	}

	checkV1Value(t, "NTChallengeResponse", client.ntChallengeResponse[0:24], "67c43011f30298a2ad35ece64f16331c44bdbed927841f94", nil)
	checkV1Value(t, "LMChallengeResponse", client.lmChallengeResponse, "98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13", nil)
	checkV1Value(t, "SessionBaseKey", client.sessionBaseKey, "d87262b0cde4b1cb7499becccdf10784", nil)
	checkV1Value(t, "KeyExchangeKey", client.keyExchangeKey, "d87262b0cde4b1cb7499becccdf10784", nil)

	checkV1Value(t, "EncryptedRandomSessionKey", client.encryptedRandomSessionKey, "518822b1b3f350c8958682ecbb3e3cb7", nil)
	checkV1Value(t, "client seal key", client.ClientSealingKey, "55555555555555555555555555555555", nil)
	// 3.4.5.2: No signing key as extended session security is not negotiated
	checkV1Value(t, "client signing key", client.ClientSigningKey, "", nil)

	// Check wrap algorithm
	encmessage, mac, err := client.Wrap(utf16FromString("Plaintext"), 0)
	if err != nil {
		t.Errorf("Error generating authenticate message: %s", err)
		t.FailNow()
	}

	checkV1Value(t, "Encrypted message", encmessage, "56fe04d861f9319af0d7238a2e3b4d457fb8", nil)

	// 3.4.4.1: Random pad is set to 00 00 00 00
	checkV1Value(t, "MAC", mac, "010000000000000009dcd1df2e459d36", nil)
}

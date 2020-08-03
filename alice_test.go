// Package pecunia, this file contains test functions for Pecunia endpoints. Execute each test by separate.
//
// @author Manuel Sales (assetverse.com 2020/08/03)
//
package alice

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

var userId *string
var id *string
var email *string
var name *string
var surname *string

func TestMain(m *testing.M) {
	// try to read par string
	userId = flag.String("userId", "XXlOdxa7UMkKAz53", "")
	id = flag.String("id", "6f9f1090-251e-4d32-bda0-94aa8ce32eda", "")
	email = flag.String("email", "my@email.com", "")
	name = flag.String("name", "Name", "")
	surname = flag.String("surname", "Surname", "")
	flag.Parse()

	// execute test and quit when ended
	v := m.Run()
	os.Exit(v)
}

func TestAliceNewUser(t *testing.T) {
	// get the session token
	sessionToken, err := AuthSessionToken()
	if err != nil {
		t.Errorf("AuthSessionToken %s", err)
		return
	}
	fmt.Printf("sessionToken:%s tsTill:%d\n", sessionToken.Token, sessionToken.Till)

	// get the session token
	backendToken, err := AuthBackendToken(ServiceOnboarding)
	if err != nil {
		t.Errorf("AuthBackendToken %s", err)
		return
	}
	fmt.Printf("backendToken:%s exp:%d\n", backendToken.Token, backendToken.Till)

	// get the user id
	userId, err := GetUser(map[string]string{"email": *email, "first_name": *name, "last_name": *surname})
	if err != nil {
		t.Errorf("GetUser %s", err)
		return
	}
	fmt.Printf("userId:%s\n", userId) // userId is a string with 16 chars, ex "XXlOdxa7UMkKAz53"
}

// TestAliceReport does the unit test of the alice package functions to get the user report
func TestAliceReport(t *testing.T) {
	userToken := &AuthToken{Token: ""} // if "get" the userToken is obtained, if "" it will be obtained later, if set it will be used the one set

	// get the backend user token
	if userToken.Token == "get" {
		token, err := AuthBackendUserToken(ServiceOnboarding, *userId)
		if err != nil {
			t.Errorf("AuthBackendUserToken %s", err)
			return
		}
		userToken = token
		fmt.Printf("userToken:%s tsTill:%d\n", token.Token, token.Till)
	}

	// get the user report
	raw, err := GetReport(*userId, userToken)
	if err != nil {
		t.Errorf("GetReport %s", err)
		return
	} else if uiStr, okUi := GetMultiMapStr(raw, "report", "user_summary", "user_id"); !okUi {
		t.Errorf("GetReport not same userId %s:%v", *userId, uiStr)
	}
	PrintMultiMap(raw)
}

// TestAliceCheck does the unit test of the alice package functions to check the report
func TestAliceCheck(t *testing.T) {
	sd := make(map[string]string)
	// check the report
	if code, raw, err := CheckReport(*userId, sd, false); err != nil {
		t.Errorf("CheckReport %s", err)
	} else {
		if code != 0 {
			PrintMultiMap(raw)
		}
		fmt.Printf("CheckReport userId:%s code:%d sd:%v\n", *userId, code, sd)
	}
}

// TestAliceOnline does the unit test of the alice package functions to get the user online token
func TestAliceOnline(t *testing.T) {
	// get the user token
	userToken, err := AuthUserToken(ServiceOnboarding, *userId)
	if err != nil {
		t.Errorf("AuthUserToken %s", err)
		return
	}
	fmt.Printf("userId:%s userToken:%s tsTill:%d\n", *userId, userToken.Token, userToken.Till)
}

// TestAliceGenCert does the unit test of the alice package functions to get the certificate
func TestAliceGenCert(t *testing.T) {
	// get the certificate
	certificate, err := CreateCertificate(*userId, "", &AuthToken{})
	if err != nil {
		t.Errorf("CreateCertificate %s", err)
		return
	}
	fmt.Printf("userId:%s certificate:%s\n", *userId, certificate)
}

// TestAliceListCerts does the unit test of the alice package functions to get the user certificates
func TestAliceListCerts(t *testing.T) {
	// get the certificates
	certificates, tss, last, err := GetCertificates(*userId, &AuthToken{})
	if err != nil {
		t.Errorf("GetCertificates %s", err)
		return
	}
	fmt.Printf("userId:%s certificates:%v tss:%v last:%d\n", *userId, certificates, tss, last)
}

// TestAliceGetCert does the unit test of the alice package functions to download the user certificate
func TestAliceGetCert(t *testing.T) {
	// get the certificates
	fileLen, err := GetCertificate(*id, *userId, &AuthToken{})
	if err != nil {
		t.Errorf("GetCertificate %s", err)
		return
	}
	fmt.Printf("userId:%s certId:%s fileLen:%d\n", *userId, *id, fileLen)
}

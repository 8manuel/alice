// Package alice contains functions to interact with Alice Biometrics for doing the KYC.
//
// @author Manuel Sales (assetverse.com 2020/08/03)
//
// The link https://docs.alicebiometrics.com/onboarding/index.html contains how to communicate with Alice for doing the digital on-boarding and KYC/AML compliance.
// This module implements the calls to Alice backend to obtain the id and tokens used in the online client.
// The online client using the id, token and the web/android/ios sdk captures the photo, id front, id back and performs the liveness test.
// When done it communicates with the backend to complete the process generating the certificate and communicating to the entity that needs the KYC (in our case Pecunia)
//
// Alice auth backend is at https://apis.alicebiometrics.com/auth/ui/#/ ; it is required to put in the header the apikey; the following services are used:
//  - GET /login_token -H "accept: application/json"curl -H "X-Consumer-Custom-ID: User" -H "apikey: ApiKey"; returns a {token:sessionToken}
//  - GET /backend_token/onboarding -H "accept: application/json" -H "Authorization: bearer sessionToken"; returns a {token:backendToken}
//  - GET /user_token/onboarding/userId -H "accept: application/json" -H "Authorization: bearer sessionToken"; returns userToken
//
// Alice onboarding backend is at https://apis.alicebiometrics.com/onboarding/ui/#/ ; the following services are used:
// - POST /user -H "accept: application/json" -H "Content-Type: multipart/form-data" -H "Authorization: bearer backendToken", returns {user_id:userId}
//
// Steps to obtain the userToken: 1 GET login_token(apiKey)>>sessionToken, 2 GET backend_token(sessionToken)>>backendToken, 3 POST user(backendToken)>>userId
//
package alice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// error codes
const Incomplete = 1
const BadExpiry = 2
const DateFormat = 3
const BadMrz = 4
const BadPhoto = 5

// Threshold values for the document face and the selfie; if the score returned is >= they are considered valid
const FaceOk = 0.5
const SelfieOk = 0.7

// cli is the http client do api requests
var cli = http.DefaultClient

// ServiceOnboarding Alice onboarding service
const ServiceOnboarding = "onboarding"

// User the Alice provided user
var User = "assetverse-trial"

// ApiKey the Alice provided apiKey
var ApiKey = "!!! PUT YOUR API KEY HERE !!!"

// UrlAuth the url of the Alice auth backend
var UrlAuth = "https://apis.alicebiometrics.com/auth"

// UrlOnboard the url of the Alice onboarding backend
var UrlOnboard = "https://apis.alicebiometrics.com/onboarding"

// AuthToken struct to contain the token and its expiry (all Alice Auth backend tokens have 1h expiry)
type AuthToken struct {
	Token string // token
	Till  int64  // valid till epoch timestamp when expires the session token
}

// SessionToken the current session token
var SessionToken AuthToken

// BackendToken map with the current backend tokens for each service
var BackendToken = make(map[string]AuthToken)

// Init initialize the Alice credentials and urls; the values empty are ignored.
func Init(user, apiKey, urlAuth, urlOnboard string) {
	if user != "" {
		User = user
	}
	if apiKey != "" {
		ApiKey = apiKey
	}
	if urlOnboard != "" {
		UrlOnboard = urlOnboard
	}
	if urlAuth != "" {
		UrlAuth = urlAuth
	}
}

// AuthSessionToken obtains the sessionToken from the Alice Auth backend using the apiKey; it also returns the expiry of the token.
func AuthSessionToken() (sessionToken AuthToken, err error) {
	var raw map[string]interface{}
	SessionToken.Till = time.Now().Unix() + 3599 // token valid for 1h; add to current time 59min+59seconds to get the expiry
	if raw, err = DoRequest(UrlAuth, "login_token", "GET", map[string]string{"X-Consumer-Custom-ID": User, "ApiKey": ApiKey}, nil, nil, nil, nil); err == nil {
		sessionToken.Token = raw["token"].(string)
		SessionToken = sessionToken
	}
	return
}

// AuthBackendToken obtains the backendToken from the Alice Auth backend using the sessionToken (if not available the function obtains it automatically).
func AuthBackendToken(service string) (backendToken *AuthToken, err error) {
	// if session expired get a new token
	if SessionToken.Till <= time.Now().Unix() {
		if _, err = AuthSessionToken(); err != nil {
			return
		}
	}
	// get the backend token
	var raw map[string]interface{}
	backendToken = &AuthToken{}
	backendToken.Till = time.Now().Unix() + 3599 // token valid for 1h; add to current time 59min+59seconds to get the expiry
	if raw, err = DoRequest(UrlAuth, "backend_token/"+service, "GET", map[string]string{"Authorization": "bearer " + SessionToken.Token}, nil, nil, nil, nil); err == nil {
		backendToken.Token = raw["token"].(string)
		BackendToken[service] = *backendToken
	}
	return
}

// AuthBackendUserToken obtains the backend userToken from the Alice Auth backend using the sessionToken (if not available the function obtains it automatically).
func AuthBackendUserToken(service, userId string) (userToken *AuthToken, err error) {
	// if session expired get a new token
	if SessionToken.Till <= time.Now().Unix() {
		if _, err = AuthSessionToken(); err != nil {
			return
		}
	}
	// get the backend token
	userToken = &AuthToken{Till: time.Now().Unix() + 3599} // token valid for 1h; add to current time 59min+59seconds to get the expiry
	var raw map[string]interface{}
	if raw, err = DoRequest(UrlAuth, "backend_token/"+service+"/"+userId, "GET", map[string]string{"Authorization": "bearer " + SessionToken.Token}, nil, nil, nil, nil); err == nil {
		userToken.Token = raw["token"].(string)
	}
	return
}

// AuthUserToken obtains the userToken from the Alice Auth backend using the sessionToken (if not available the function obtains it automatically).
func AuthUserToken(service, userId string) (userToken AuthToken, err error) {
	// if session expired get a new token
	if SessionToken.Till <= time.Now().Unix() {
		if _, err = AuthSessionToken(); err != nil {
			return
		}
	}
	// get the backend token
	userToken.Till = time.Now().Unix() + 3599 // token valid for 1h; add to current time 59min+59seconds to get the expiry
	var raw map[string]interface{}
	if raw, err = DoRequest(UrlAuth, "user_token/"+service+"/"+userId, "GET", map[string]string{"Authorization": "bearer " + SessionToken.Token}, nil, nil, nil, nil); err == nil {
		userToken.Token = raw["token"].(string)
	}
	return
}

// GetUser obtains the userId from the Alice Onboarding backend using the onboarding backendToken (if not available the function obtains it automatically).
// The formParams are optional (can be nil); there are the following ones: device_model device_platform device_platform_version email first_name last_name
func GetUser(formParams map[string]string) (userId string, err error) {
	// if not backendToken get one
	if st, ok := BackendToken[ServiceOnboarding]; !ok || st.Till <= time.Now().Unix() {
		if _, err = AuthBackendToken(ServiceOnboarding); err != nil {
			return
		}
	}
	// get the user id
	var raw map[string]interface{}
	if raw, err = DoRequest(UrlOnboard, "user", "POST", map[string]string{"Authorization": "bearer " + BackendToken[ServiceOnboarding].Token}, formParams, nil, nil, nil); err == nil {
		userId = raw["user_id"].(string)
	}
	return
}

// GetReport obtains json report of a userId from the Alice Onboarding backend using the onboarding backend userToken (if not available the function obtains it automatically).
// The formParams are optional (can be nil); there are the following ones: device_model device_platform device_platform_version email first_name last_name
func GetReport(userId string, userToken *AuthToken) (raw map[string]interface{}, err error) {
	// if not backendToken get one
	if userToken.Token == "" {
		if userToken, err = AuthBackendUserToken(ServiceOnboarding, userId); err != nil {
			return
		}
	}
	// get the report
	if raw, err = DoRequest(UrlOnboard, "user/report", "GET", map[string]string{"Authorization": "bearer " + userToken.Token}, nil, nil, nil, nil); err == nil {
	}
	return
}

// CheckReport returns a map for the Kyc; if voidBad it voids the selfie/document that not meets the validations
func CheckReport(userId string, sd map[string]string, voidBad bool) (code int, raw map[string]interface{}, err error) {
	// get the report
	var userToken *AuthToken
	if userToken, err = AuthBackendUserToken(ServiceOnboarding, userId); err != nil {
		return
	} else if raw, err = GetReport(userId, userToken); err != nil {
		return
	}

	// compose the map with the data for the client
	var sm map[string]interface{}
	var mrz, face, selfie float64
	var doc, docType string
	if sa, ok := GetMultiMapArr(raw, "report", "user_summary", "documents", "uploaded_documents"); ok && len(sa) > 0 {
		for _, doc = range sa {
			if voided, vOk := GetMultiMapBool(raw, "report", "document_reports", doc, "voided"); vOk && voided {
				continue // skip voided document
			}
			docType, _ = GetMultiMapStr(raw, "report", "document_reports", doc, "type")
			//println("doc", doc, "type", docType)
			if docType == "idcard" {
				if sm, ok = GetMultiMapMap(raw, "report", "document_reports", doc, "sides", "back", "fields"); ok && len(sm) > 0 {
					sd["userId"] = userId
					sd["issuer"], _ = GetMultiMapStr(raw, "report", "document_reports", doc, "issuing_country")
					sd["nation"], _ = GetMultiMapStr(sm, "nationality", "value")
					sd["docType"], _ = GetMultiMapStr(sm, "document_type", "value")
					sd["docId"], _ = GetMultiMapStr(sm, "id_number", "value")
					sd["expiry"], _ = GetMultiMapStr(sm, "expiration_date", "value")
					sd["name"], _ = GetMultiMapStr(sm, "first_name", "value")
					sd["surname"], _ = GetMultiMapStr(sm, "last_name", "value")
					sd["birthDat"], _ = GetMultiMapStr(sm, "birth_date", "value")
					sd["birthPla"], _ = GetMultiMapStr(sm, "birth_place", "value")
					sd["sex"], _ = GetMultiMapStr(sm, "sex", "value")
					sd["address"], _ = GetMultiMapStr(sm, "address", "value")
					sd["city"], _ = GetMultiMapStr(sm, "city", "value")
					sd["prov"], _ = GetMultiMapStr(sm, "province", "value")

					mrz, _ = GetMultiMapFlo(sm, "mrz", "status", "info", "0", "code")
					face, _ = GetMultiMapFlo(raw, "report", "document_reports", doc, "face_validation", "score")
					break
				}
			} else if docType == "passport" {
				if sm, ok = GetMultiMapMap(raw, "report", "document_reports", doc, "sides", "front", "fields"); ok && len(sm) > 0 {
					sd["userId"] = userId
					sd["issuer"], _ = GetMultiMapStr(sm, "country", "value")
					sd["nation"], _ = GetMultiMapStr(sm, "nationality", "value")
					sd["docType"], _ = GetMultiMapStr(sm, "document_type", "value")
					sd["docId"], _ = GetMultiMapStr(sm, "passport_number", "value")
					sd["expiry"], _ = GetMultiMapStr(sm, "expiration_date", "value")
					sd["name"], _ = GetMultiMapStr(sm, "first_name", "value")
					sd["surname"], _ = GetMultiMapStr(sm, "last_name", "value")
					sd["birthDat"], _ = GetMultiMapStr(sm, "birth_date", "value")
					sd["birthPla"] = "" // not present
					sd["sex"], _ = GetMultiMapStr(sm, "sex", "value")
					sd["address"] = "" // not present
					sd["city"] = ""    // not present
					sd["prov"] = ""    // not present

					mrz, _ = GetMultiMapFlo(sm, "mrz", "status", "info", "0", "code")
					face, _ = GetMultiMapFlo(raw, "report", "document_reports", doc, "face_validation", "score")
					break
				}
			}
		}
	}
	selfie, _ = GetMultiMapFlo(raw, "report", "user_summary", "selfie", "liveness", "score") // if zero we assume there is no selfie
	sd["doc"] = doc
	sd["mrz"] = strconv.FormatFloat(mrz, 'f', -1, 64)
	sd["face"] = strconv.FormatFloat(face, 'f', -1, 64)
	sd["selfie"] = strconv.FormatFloat(selfie, 'f', -1, 64)

	// if found the data check report to return the check code (err if expired, mrz!=2301, face<0.5, selfie<0.7 ); finally convert into a json
	var st time.Time
	if len(sd) == 0 || sd["expiry"] == "" {
		code, sd["err"] = Incomplete, "report incomplete"
	} else if st, err = time.Parse("2006-01-02", sd["expiry"]); err != nil {
		code, sd["err"] = BadExpiry, "bad expiry date format"
	} else if time.Now().Unix()+60*24*360 > st.Unix() {
		code, sd["err"] = BadExpiry, "expired or closer to expiry"
	} else if mrz != 2301 {
		code, sd["err"] = BadMrz, "bad document mrz"
	} else if face < FaceOk || selfie < SelfieOk {
		code, sd["err"] = BadPhoto, "face/selfie score not passed"
	}

	// if voidBad void the document expired, with bad mrz or score; if voidBad and bad selfie void it also
	if err == nil && voidBad && (code == BadExpiry || code == BadMrz || (face > 0 && face < FaceOk)) {
		if raw, err = DoRequest(UrlOnboard, "user/document/"+doc, "PATCH", map[string]string{"Authorization": "bearer " + userToken.Token}, nil, nil, nil, nil); err == nil {
			face = 1
		}
	}
	if err == nil && voidBad && selfie > 0 && selfie < SelfieOk {
		if raw, err = DoRequest(UrlOnboard, "user/selfie", "PATCH", map[string]string{"Authorization": "bearer " + userToken.Token}, nil, nil, nil, nil); err == nil {
			selfie = 1
		}
	}
	if err == nil && voidBad && (code == BadExpiry || code == BadMrz || code == BadPhoto) {
		code, sd["err"] = Incomplete, "report incomplete" // set code to incomplete if document/selfie void successful
	}

	return
}

// CreateCertificate creates the user certificate (Signed PDF Report) from uploaded and processed data and if al ok returns the certificateId.
// Once obtained with GET ​/user​/certificate​/{certificateId} the certificate can be downloaded
func CreateCertificate(userId, template string, userToken *AuthToken) (certificateId string, err error) {
	// if not backendToken get one
	if userToken.Token == "" {
		if userToken, err = AuthBackendUserToken(ServiceOnboarding, userId); err != nil {
			return
		}
	}
	if template == "" {
		template = "default"
	}
	// request to generate the certificate
	jsonArr, _ := json.Marshal(map[string]string{"template_name": template})
	var raw map[string]interface{}
	if raw, err = DoRequest(UrlOnboard, "user/certificate", "POST", map[string]string{"Authorization": "bearer " + userToken.Token}, nil, jsonArr, nil, nil); err == nil {
		certificateId = raw["certificate_id"].(string)
	}
	return
}

// GetCertificates the certificates for a userId; it returns an array of certificates, an array of the certificates timestamp and the index of the last timestamp.
func GetCertificates(userId string, userToken *AuthToken) (certificates []string, tss []int64, last int, err error) {
	// if not backendToken get one
	if userToken.Token == "" {
		if userToken, err = AuthBackendUserToken(ServiceOnboarding, userId); err != nil {
			return
		}
	}
	// get the certificate
	var raw map[string]interface{}
	if raw, err = DoRequest(UrlOnboard, "user/certificates", "GET", map[string]string{"Authorization": "bearer " + userToken.Token}, nil, nil, nil, nil); err == nil {
		if arrI, okI := GetMultiMap(raw, "certificates"); okI {
			if arr, ok := arrI.([]interface{}); ok {
				certificates, tss = make([]string, len(arr)), make([]int64, len(arr))
				var creAt string
				var st time.Time
				for i, v := range arr {
					if vr, okM := v.(map[string]interface{}); okM {
						certificates[i], _ = GetMultiMapStr(vr, "certificate_id")
						creAt, _ = GetMultiMapStr(vr, "created_at")
						if st, err = time.Parse(time.RFC3339, creAt+"Z"); err != nil {
							return
						} else if tss[i] = st.Unix(); i > 0 && tss[i] > tss[last] {
							last = i
						}
					}
				}
			}
		}
	}
	return
}

// GetCertificate downloads the pdf with the certificate.
func GetCertificate(certificateId, userId string, userToken *AuthToken) (fileLen int, err error) {
	// if not backendToken get one
	if userToken.Token == "" {
		if userToken, err = AuthBackendUserToken(ServiceOnboarding, userId); err != nil {
			return
		}
	}
	// get the certificate
	var raw map[string]interface{}
	filePath := userId + ".pdf"
	raw, err = DoRequest(UrlOnboard, "user/certificate/"+certificateId, "GET", map[string]string{"Authorization": "bearer " + userToken.Token}, nil, nil, nil, &filePath)
	if err == nil && raw["fileLen"] != nil {
		fileLen = raw["fileLen"].(int)
	}
	return
}

// DoRequest build the request (method POST, GET, ..; depending on the recuest, use the header/query/formParams)
func DoRequest(backend, path, method string, headerParams, formParams map[string]string, jsonArr []byte, queryParams url.Values, filePath *string) (raw map[string]interface{}, err error) {
	if headerParams == nil {
		headerParams = make(map[string]string)
	}
	// if formParams set convert to multipart/form-data; if jsonArr convert to application/json
	body := &bytes.Buffer{}
	if formParams != nil && len(formParams) > 0 {
		var fw io.Writer
		w := multipart.NewWriter(body)
		for k, v := range formParams {
			if fw, err = w.CreateFormField(k); err != nil {
				return
			} else if _, err = fw.Write([]byte(v)); err != nil {
				return
			}
		}
		w.Close()
		headerParams["Content-Type"] = w.FormDataContentType()
	} else if len(jsonArr) > 0 {
		body = bytes.NewBuffer(jsonArr)
		headerParams["Content-Type"] = "application/json"
	}

	// Setup path and query paramters
	fullpath := backend + "/" + path
	url, err := url.Parse(fullpath)
	if err != nil {
		return
	}
	// Adding Query Param
	query := url.Query()
	for k, v := range queryParams {
		for _, iv := range v {
			query.Add(k, iv)
		}
	}
	// Encode the parameters.
	url.RawQuery = query.Encode()

	// Generate a new request
	var req *http.Request
	if body != nil {
		req, err = http.NewRequest(method, url.String(), body)
	} else {
		req, err = http.NewRequest(method, url.String(), nil)
	}
	if err != nil {
		return
	}
	// add header parameters, if any
	if len(headerParams) > 0 {
		headers := http.Header{}
		for h, v := range headerParams {
			headers.Set(h, v)
		}
		req.Header = headers
	}
	// add the user agent to the request.
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "Swagger-Custom/0.1.0/go")
	//fmt.Printf("header:%v\n", req.Header)

	// do the request
	var res *http.Response
	if res, err = cli.Do(req); err != nil || res == nil {
		return
	}
	defer res.Body.Close()
	//fmt.Printf("Alice %s statusCode:%d\n", path, res.StatusCode)
	if res.StatusCode >= 300 {
		return raw, fmt.Errorf(res.Status)
	}

	// if filePath set extract the body into a file at filePath; if not set extract into raw the data from the response body
	if filePath != nil {
		var fileLen int
		fileLen, err = WriteFile(*filePath, res.Body)
		raw = map[string]interface{}{"fileLen": fileLen}
		println("XXX", *filePath, fileLen)
		//*bodyArr, err = ioutil.ReadAll(res.Body)
	} else {
		jdec := json.NewDecoder(res.Body)
		jdec.UseNumber()
		raw = make(map[string]interface{})
		err = jdec.Decode(&raw)
	}
	return
}

// WriteFile saves in a file at filePath the stream
func WriteFile(filePath string, stream io.Reader) (fileLen int, err error) {
	f, err := os.Create(filePath)
	if err != nil {
		return
	}
	defer f.Close()
	// loop
	var l, n int
	p := make([]byte, 1024*64)
	for {
		if n, err = stream.Read(p); err == io.EOF {
			err = nil
		}
		if err != nil || n == 0 {
			break
		} else if l, err = f.Write(p[:n]); err != nil || l != n {
			break
		}
		fileLen += l
	}
	return
}

// GetMultiMap returns the value of a multimap with the keys provided (if the key can be parsed into a number the multimap is an array and the key is the index)
func GetMultiMap(raw map[string]interface{}, keys ...string) (val interface{}, ok bool) {
	var sm map[string]interface{}
	val, ok = raw[keys[0]]
	for i := 1; ok && i < len(keys); i++ {
		if keyNum, err := strconv.Atoi(keys[i]); err == nil { // key is the array index
			if sa, oka := val.([]interface{}); !oka {
				return val, false
			} else {
				val = sa[keyNum]
			}
		} else {
			if sm, ok = val.(map[string]interface{}); !ok { // key is the map key
				return
			}
			val, ok = sm[keys[i]]
		}
	}
	return
}

// GetMultiMapStr returns the string value of a multimap with the keys provided (as this function is used a lot to get the val it is not called GetMultiMap so it is more efficient)
func GetMultiMapStr(raw map[string]interface{}, keys ...string) (valStr string, ok bool) {
	var val interface{}
	var sm map[string]interface{}
	val, ok = raw[keys[0]]
	for i := 1; ok && i < len(keys); i++ {
		if sm, ok = val.(map[string]interface{}); !ok {
			return
		}
		val, ok = sm[keys[i]]
	}
	if ok {
		valStr, ok = val.(string)
	}
	return
}

// GetMultiMapBool returns the boolean value of a multimap with the keys provided
func GetMultiMapBool(raw map[string]interface{}, keys ...string) (valBool bool, ok bool) {
	var val interface{}
	if val, ok = GetMultiMap(raw, keys...); !ok {
		return
	}
	valBool, ok = val.(bool)
	return
}

// GetMultiMapFlo returns the float value of a multimap with the keys provided
func GetMultiMapFlo(raw map[string]interface{}, keys ...string) (valFlo float64, ok bool) {
	var val interface{}
	if val, ok = GetMultiMap(raw, keys...); !ok {
		return
	}
	var valNum json.Number
	if valNum, ok = val.(json.Number); ok {
		var err error
		valFlo, err = valNum.Float64()
		ok = err == nil
	}
	return
}

// GetMultiMapArr returns the array string value of a multimap with the keys provided
func GetMultiMapArr(raw map[string]interface{}, keys ...string) (valArr []string, ok bool) {
	var val interface{}
	if val, ok = GetMultiMap(raw, keys...); !ok {
		return
	}
	if valSi, oki := val.([]interface{}); oki {
		valArr = make([]string, len(valSi))
		for k, v := range valSi {
			valArr[k], _ = v.(string)
		}
	}
	return
}

// GetMultiMapMap returns the array string value of a multimap with the keys provided
func GetMultiMapMap(raw map[string]interface{}, keys ...string) (valMap map[string]interface{}, ok bool) {
	var val interface{}
	if val, ok = GetMultiMap(raw, keys...); !ok {
		return
	}
	valMap, ok = val.(map[string]interface{})
	return
}

// PrintMultiMap prints report decoded json structure
func PrintMultiMap(raw map[string]interface{}) {
	// loop raw map, if not nested map print directly otherwise loop nested map (only 3 nestings done)
	for k0, v0 := range raw {
		m0, ok0 := v0.(map[string]interface{})
		if !ok0 {
			fmt.Printf("%s:%v\n", k0, v0)
			continue
		}
		fmt.Printf("%s\n", k0)
		for k1, v1 := range m0 {
			m1, ok1 := v1.(map[string]interface{})
			if !ok1 {
				fmt.Printf(". %s:%v\n", k1, v1)
				continue
			}
			fmt.Printf(". %s\n", k1)
			for k2, v2 := range m1 {
				m2, ok2 := v2.(map[string]interface{})
				if !ok2 {
					fmt.Printf(". . %s:%v\n", k2, v2)
					continue
				}
				fmt.Printf(". . %s\n", k2)
				for k3, v3 := range m2 {
					m3, ok3 := v3.(map[string]interface{})
					if !ok3 || k3 != "sides" {
						fmt.Printf(". . . %s:%v\n", k3, v3)
						continue
					}
					fmt.Printf(". . . %s\n", k3)
					for k4, v4 := range m3 {
						m4, ok4 := v4.(map[string]interface{})
						if !ok4 {
							fmt.Printf(". . . . %s:%v\n", k4, v4)
							continue
						}
						fmt.Printf(". . . . %s\n", k4)
						for k5, v5 := range m4 {
							m5, ok5 := v5.(map[string]interface{})
							if !ok5 || k5 != "fields" {
								fmt.Printf(". . . . . %s:%v\n", k5, v5)
								continue
							}
							fmt.Printf(". . . . . %s\n", k5)
							for k6, v6 := range m5 {
								fmt.Printf(". . . . . . %s:%v\n", k6, v6)
							}
						}
					}
				}
			}
		}
	}
}

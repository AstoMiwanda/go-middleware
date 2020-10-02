package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
)

// HTTPHandlerFunc type for handle func http
type HTTPHandlerFunc func(http.ResponseWriter, *http.Request)

/* PUBLIC VARIABLE */
/* -------------------------------------------------------- */
var jwtKey = GetPassToken()
var applicationName = GetEnvVal("NAMA_APLIKASI")
var apiName = GetEnvVal("NAMA_API")
var ipAPI string
var statusHTTPResp int

/* -------------------------------------------------------- */

// AuthToken function for auth jwt token when client hit API
// var AuthToken = func(token string) (Claims, string) {
// 	claims := &Claims{}
//
// 	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
// 		return jwtKey, nil
// 	})
//
// 	if err != nil {
// 		return *claims, err.Error()
// 	}
//
// 	if !tkn.Valid {
// 		return *claims, "Token is not valid."
//
// 	}
//
// 	return *claims, ""
// }

func main() {
	log.Print("asto azza")
}

// GetToken function for auth jwt token when client hit API
var GetToken = func(w http.ResponseWriter, r *http.Request) {
	var data []map[string]interface{}
	var token map[string]interface{}
	statusHTTPResp = http.StatusOK
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	ipAPI = ip
	reqBody, errParse := ioutil.ReadAll(r.Body)
	if errParse != nil {
		statusHTTPResp = http.StatusBadRequest
		JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), nil)
		return
	}

	if err := json.Unmarshal(reqBody, &token); err != nil {
		statusHTTPResp = http.StatusBadRequest
		JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), err.Error())
		return
	}
	nik := token["nik"].(string)
	r.Body = ioutil.NopCloser(bytes.NewReader(reqBody))

	tokenHeader := r.Header.Get("Authorization")
	if tokenHeader == "" {
		res := Message(false, http.StatusText(http.StatusBadRequest))
		res["data"] = nil
		Respond(w, res)
		return

	}

	splitted := strings.Split(tokenHeader, " ")
	if len(splitted) != 2 || splitted[0] != "Bearer" {
		resp := Message(false, http.StatusText(http.StatusUnauthorized))
		resp["data"] = nil
		Respond(w, resp)
		return

	}

	tokenHeader = splitted[1]
	secretKey, err := ValidateSecretKey(tokenHeader)

	if secretKey == (SecretKey{}) || err != nil {
		statusHTTPResp = http.StatusUnauthorized
		JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), nil)
		return
	} else if secretKey.APIName == GetEnvVal("NAMA_API_MOBILE") {
		ipAPI = GetEnvVal("IP_MOBILE")
		apiName = GetEnvVal("NAMA_API_MOBILE")
	}

	log.Print("ip: " + ipAPI)
	log.Print("ip db: " + secretKey.IP)

	if secretKey.Name != applicationName || secretKey.APIName != apiName || secretKey.IP != ipAPI {
		statusHTTPResp = http.StatusUnauthorized
		message := fmt.Sprintf("Access denied for IP %s", ipAPI)
		JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), message)
		return
	}

	tokenString, err := GenerateToken(secretKey, nik)

	if err != nil {
		statusHTTPResp = http.StatusInternalServerError
		JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), err)
		return
	}

	dataSingle := map[string]interface{}{
		"nama_aplikasi": secretKey.Name,
		"access_token":  tokenString,
	}
	data = append(data, dataSingle)

	JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), data)
	return
}

// AuthTokenMiddleware function for auth jwt token when client hit API
var AuthTokenMiddleware = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notAuth := []string{
			"/token",
			"/apps/icon",
			"/signature-get",
			GetEnvVal("URI_UPLOADS_DOCUMENT_REPORT_ALKER"),
			GetEnvVal("URI_UPLOADS_IMAGE_QC_MATERIAL"),
			GetEnvVal("URI_UPLOADS_FILE_QC_MATERIAL"),
		}
		requestPath := r.URL.Path
		requestDir := path.Dir(requestPath)
		statusHTTPResp = http.StatusOK
		tmp := []rune(requestPath)
		requestDirHashAlker := byPassURI(tmp, GetEnvVal("URI_UPLOADS_DOCUMENT_REPORT_ALKER"))
		requestDirHashQCMaterialImage := byPassURI(tmp, GetEnvVal("URI_UPLOADS_IMAGE_QC_MATERIAL"))
		requestDirHashQCMaterialFile := byPassURI(tmp, GetEnvVal("URI_UPLOADS_FILE_QC_MATERIAL"))
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		ipAPI = ip

		for _, value := range notAuth {

			if value == requestPath ||
				value == requestDir ||
				value == requestDirHashAlker ||
				value == requestDirHashQCMaterialImage ||
				value == requestDirHashQCMaterialFile {
				next.ServeHTTP(w, r)
				return
			}
		}

		tokenHeader := r.Header.Get("Authorization")
		if tokenHeader == "" {
			res := Message(false, http.StatusText(http.StatusBadRequest))
			res["data"] = nil
			Respond(w, res)
			return

		}

		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 || splitted[0] != "Bearer" {
			resp := Message(false, http.StatusText(http.StatusUnauthorized))
			resp["data"] = nil
			Respond(w, resp)
			return

		}

		tokenHeader = splitted[1]
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tokenHeader, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			statusHTTPResp = http.StatusUnauthorized
			JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), err.Error())
			return
		}

		if !tkn.Valid {
			statusHTTPResp = http.StatusForbidden
			JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), nil)
			return

		}

		if CompareHash(claims.APIName, []byte(GetEnvVal("NAMA_API_MOBILE"))) {
			ipAPI = GetEnvVal("IP_MOBILE")
			apiName = GetEnvVal("NAMA_API_MOBILE")
		}

		if claims.Name != applicationName || !CompareHash(claims.IP, []byte(ipAPI)) {
			statusHTTPResp = http.StatusForbidden
			message := fmt.Sprintf("Access denied for IP %s", ipAPI)
			JSON(w, statusHTTPResp, http.StatusText(statusHTTPResp), message)
			return
		}

		context.Set(r, "nik", claims.NIK)
		next.ServeHTTP(w, r)

	})
}

// byPassUri func to generate dir pass
func byPassURI(tmp []rune, URI string) string {
	lenURI := len(URI)
	lenTmp := len(tmp)
	if lenTmp >= lenURI {
		return string(tmp[0:lenURI])
	}
	return ""
}

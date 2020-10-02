package middleware

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
)

var db = GetDB()

// HashAndSalt to hash and salt user's password with bcrypt
// @param []byte user's password
// @return string hashed user's password
func HashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}

	return string(hash)
}

// CompareHash to compare user's password
// @param string hashed user's password, []byte user's password entered
// @return bool result compare user's password
func CompareHash(hashedPwd string, plainPwd []byte) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

// ValidateSecretKey for validate secret key
func ValidateSecretKey(key string) (SecretKey, error) {
	var secretKey SecretKey
	sql := ` SELECT 
		nama_aplikasi, 
		nama_api, 
		ip, 
		secret_key
		FROM
			api.api_attribut
		WHERE
			secret_key = ? `
	rows, err := db.Raw(sql, key).Rows()
	defer rows.Close()
	if err != nil {
		return secretKey, err
	}

	for rows.Next() {
		if err := rows.Scan(
			&secretKey.Name,
			&secretKey.APIName,
			&secretKey.IP,
			&secretKey.Key,
		); err != nil {
			log.Fatal(err.Error())
		}
	}
	return secretKey, nil
}

// GenerateToken for generate new token
func GenerateToken(secretKey SecretKey, nik string) (string, error) {
	expirationTime := time.Now().Add(60 * time.Minute)
	claims := &Claims{
		NIK:     nik,
		Name:    secretKey.Name,
		APIName: HashAndSalt([]byte(secretKey.APIName)),
		IP:      HashAndSalt([]byte(secretKey.IP)),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	return tokenString, err
}

// JSON response
func JSON(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	var reply Reply
	var error Error

	error.Code = statusCode
	error.Message = message
	error.Data = data

	if statusCode != 200 {
		reply.Error = &error
	} else {
		reply.Data = data
	}
	response, _ := json.Marshal(reply)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(response)

}

// Message response
func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}

// Respond response
func Respond(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// GetPassToken is for get password jwt token from env
// @param nothing
// @return []byte password jwt token
func GetPassToken() []byte {
	e := godotenv.Load()
	if e != nil {
		panic(e)
	}
	return []byte(os.Getenv("Token_Password"))
}

// IsNil is for check Null value
// @param dynamic
// @return bool false if not nil and true if null
func IsNil(request ...interface{}) bool {
	for i := 0; i < len(request); i++ {
		kindOfValue := reflect.ValueOf(request[i]).Kind().String()
		if kindOfValue == "chan" || kindOfValue == "func" || kindOfValue == "interface" || kindOfValue == "map" || kindOfValue == "pointer" || kindOfValue == "slice" {
			if reflect.ValueOf(request[i]).IsNil() {
				return true
			}
		} else {
			if request[i] == nil || request[i] == "" || request[i] == 0 {
				return true
			}
		}
	}
	return false
}

// IsNilInterface is for check Null value
// @param dynamic
// @return bool false if not nil and true if null
func IsNilInterface(request ...interface{}) bool {
	for i := 0; i < len(request); i++ {
		if reflect.ValueOf(request[i]).IsNil() {
			return true
		}
	}
	return false
}

// GetEnvVal is for get password jwt token from env
// @param nothing
// @return []byte password jwt token
func GetEnvVal(value string) string {
	e := godotenv.Load()
	if e != nil {
		panic(e)
	}
	return os.Getenv(value)
}

// RangeDate is for get password jwt token from env
func RangeDate(start, end time.Time) func() time.Time {
	y, m, d := start.Date()
	start = time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	y, m, d = end.Date()
	end = time.Date(y, m, d, 0, 0, 0, 0, time.UTC)

	return func() time.Time {
		if start.After(end) {
			return time.Time{}
		}
		date := start
		start = start.AddDate(0, 0, 1)
		return date
	}
}

// UploadFile function for upload image to server and encrypt name
func UploadFile(r *http.Request, file multipart.File, params map[string]string) (string, error) {
	extension := filepath.Ext(params["fileName"])
	tempFileName := fmt.Sprintf("%s_*%s", params["nik"], extension)
	dirYearAndMonth := time.Now().Local().UTC().Format("2006/1")

	dirName := fmt.Sprintf("%s/%s", params["dirPathParam"], dirYearAndMonth)
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		os.MkdirAll(dirName, os.ModePerm)
	}
	tempFile, err := ioutil.TempFile(dirName, tempFileName)
	if err != nil {
		return "", err
	}
	tempFileName = tempFile.Name()
	defer tempFile.Close()

	tempFileNames := strings.Split(tempFileName, "/")
	tempFileName = tempFileNames[len(tempFileNames)-1]

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}
	tempFile.Write(fileBytes)

	host := fmt.Sprintf("%s%s", GetEnvVal("BASE_URL"), GetEnvVal("PORT"))
	return fmt.Sprintf("%s%s%s/%s", host, params["uri"], dirYearAndMonth, tempFileName), nil
}

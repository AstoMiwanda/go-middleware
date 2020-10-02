package middleware

import (
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql" // go-lint
	_ "github.com/godror/godror"       // go-lint
	"github.com/jinzhu/gorm"
	"github.com/joho/godotenv"
)

var dbGorm *gorm.DB

// conDB function connection db mysql
func conDB() {

	e := godotenv.Load()
	if e != nil {
		log.Print(e)
	}

	username := os.Getenv("DB_User")
	password := os.Getenv("DB_Password")
	// dbName := os.Getenv("DB_Name")
	dbHost := os.Getenv("DB_Host")
	dbPort := os.Getenv("DB_Port")

	conn, err := gorm.Open("mysql", ""+username+":"+password+"@tcp("+dbHost+":"+dbPort+")/?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		log.Print("Error connection db")
		panic(err.Error())
	}

	dbGorm = conn
	// defer db.Close()
}

// GetDB func for get db gorm connection
func GetDB() *gorm.DB {
	conDB()
	return dbGorm
}

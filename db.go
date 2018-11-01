package main

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type test struct {
	gorm.Model
	Cert string
}

func addCert(name string) {
	db, err := gorm.Open("postgres", "host=localhost port=5432 user=certmanager dbname=certmanager password=Pass1234 sslmode=disable")
	if err != nil {
		fmt.Println(err)
		panic("failed to connect to certManager database")
	}
	defer db.Close()
	db.AutoMigrate(&test{})

	//Add cert object
	db.Create(&test{Cert: name})

}

/**
Get Domain AltNames via domain
*/
func getAltNames(domain string) (altNames []byte, err error) {
	panic("Not Implemented")
}

/**
Get User Info via email
*/
func getUserInfo(email string) (userInfo []byte, err error) {
	panic("Not Implemented")
}

/**
Get Certificate Details via Domain
*/
func getCertDeatils(domain string) (certDetails []byte, err error) {
	panic("Not Implemented")
}

/**
Save User Information key email, value userInfo
*/
func addUserInfo(email string, userInfo []byte) error {
	panic("Not Implemented")
}

/**
Save Certificate Details key domain, value certDetails
*/
func addCertDetails(domain string, certDetails []byte) error {
	panic("Not Implemented")
}

/**
Save Alt Name Details key domain, value altNames
*/
func addAltNames(domain string, altNames []byte) error {
	panic("Not Implemented")
}

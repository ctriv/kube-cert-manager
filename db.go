package main

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"log"
)

type CertDetail struct {
	gorm.Model
	Domain string `gorm:"unique"`
	Value  string
}

type DomainAltname struct {
	gorm.Model
	Domain string `gorm:"unique"`
	Value  string
}

type UserInfo struct {
	gorm.Model
	Email string `gorm:"unique"`
	Value string
}

func db() (*gorm.DB, error) {
	db, err := gorm.Open("postgres", "host=localhost port=5432 user=certmanager dbname=certmanager password=Pass1234 sslmode=disable")
	if err != nil {
		fmt.Println(err)
		panic("failed to connect to certManager database")
	}

	return db, err
}

/**
Get Domain AltNames via domain
*/
func getAltNames(domain string) (altNamesRaw []byte, err error) {
	log.Printf("Retreving domain alt-names from database for domain (%s)", domain)

	d, err := db()
	var altNames DomainAltname

	d.Where(&DomainAltname{Domain: domain}).First(&altNames)
	defer d.Close()

	altNamesRaw = []byte(altNames.Value)
	return altNamesRaw, err
}

/**
Get User Info via email
*/
func getUserInfo(email string) (userInfoRaw []byte, err error) {
	log.Printf("Retreving user info email (%s) from database", email)

	d, err := db()
	var userInfo UserInfo

	d.Where(&UserInfo{Email: email}).Find(&userInfo)
	defer d.Close()

	userInfoRaw = []byte(userInfo.Value)
	return userInfoRaw, err
}

/**
Get Certificate Details via Domain
*/
func getCertDetails(domain string) (certDetailsRaw []byte, err error) {
	log.Printf("Retreving certificate details from database for domain (%s)", domain)

	d, err := db()
	var certDetails CertDetail

	d.Where(&CertDetail{Domain: domain}).First(&certDetails)
	defer d.Close()

	certDetailsRaw = []byte(certDetails.Value)
	return certDetailsRaw, err
}

/**
Save User Information key email, value userInfo
*/
func addUserInfo(email string, userInfo []byte) error {
	log.Printf("Saving user info email (%s) to database", email)

	d, err := db()
	s := string(userInfo)

	d.Create(&UserInfo{Email: email, Value: s})
	defer d.Close()

	return err
}

/**
Save Certificate Details key domain, value certDetails
*/
func addCertDetails(domain string, certDetails []byte) error {
	log.Printf("Saving certificate details to database for domain (%s)", domain)

	d, err := db()
	s := string(certDetails)

	d.Create(&CertDetail{Domain: domain, Value: s})
	defer d.Close()

	return err
}

/**
Save Alt Name Details key domain, value altNames
*/
func addAltNames(domain string, altNames []byte) error {
	log.Printf("Saving domain alt-names to database for domain (%s)", domain)

	d, err := db()
	s := string(altNames)

	d.Create(&DomainAltname{Domain: domain, Value: s})
	defer d.Close()

	return err
}

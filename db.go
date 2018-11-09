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

func db(dbArgs string) (*gorm.DB, error) {
	db, err := gorm.Open("postgres", dbArgs)
	if err != nil {
		fmt.Println(err)
		panic("failed to connect to certManager database")
	}

	return db, err
}

/**
Get Domain AltNames via domain
*/
func getAltNames(domain string, d *gorm.DB) (altNamesRaw []byte, err error) {
	log.Printf("Retreving domain alt-names from database for domain (%s)", domain)

	var altNames DomainAltname
	d.Where(&DomainAltname{Domain: domain}).First(&altNames)
	altNamesRaw = []byte(altNames.Value)
	return altNamesRaw, err
}

/**
Get User Info via email
*/
func getUserInfo(email string, d *gorm.DB) (userInfoRaw []byte, err error) {
	log.Printf("Retreving user info email (%s) from database", email)

	var userInfo UserInfo
	d.Where(&UserInfo{Email: email}).Find(&userInfo)
	userInfoRaw = []byte(userInfo.Value)
	return userInfoRaw, err
}

/**
Get Certificate Details via Domain
*/
func getCertDetails(domain string, d *gorm.DB) (certDetailsRaw []byte, err error) {
	log.Printf("Retreving certificate details from database for domain (%s)", domain)

	var certDetails CertDetail
	d.Where(&CertDetail{Domain: domain}).First(&certDetails)
	certDetailsRaw = []byte(certDetails.Value)
	return certDetailsRaw, err
}

/**
Save User Information key email, value userInfo
*/
func addUserInfo(email string, userInfo []byte, d *gorm.DB) (err error) {
	log.Printf("Saving user info email (%s) to database", email)

	s := string(userInfo)
	d.Create(&UserInfo{Email: email, Value: s})
	return err
}

/**
Save Certificate Details key domain, value certDetails
*/
func addCertDetails(domain string, certDetails []byte, d *gorm.DB) (err error) {
	log.Printf("Saving certificate details to database for domain (%s)", domain)

	s := string(certDetails)
	d.Create(&CertDetail{Domain: domain, Value: s})
	return err
}

/**
Save Alt Names Details key domain, value altNames
*/
func addAltNames(domain string, altNames []byte, d *gorm.DB) (err error) {
	log.Printf("Saving domain alt-names to database for domain (%s)", domain)

	s := string(altNames)
	d.Create(&DomainAltname{Domain: domain, Value: s})
	return err
}

/**
Update Alt Names Details key domain, new values altNames
*/
func updateAltNames(domain string, altNamesRaw []byte, d *gorm.DB) (err error) {
	log.Printf("Updating domain alt-names to database for domain (%s)", domain)

	s := string(altNamesRaw)
	var altNames DomainAltname
	d.Where(&DomainAltname{Domain: domain}).First(&altNames)
	altNames.Value = s
	d.Save(&altNames)
	return err
}

/**
Update Certificate Details key domain, new value certDetails
*/
func updateCertDetails(domain string, certDetailsRaw []byte, d *gorm.DB) (err error) {
	log.Printf("Updating domain alt-names to database for domain (%s)", domain)

	s := string(certDetailsRaw)
	var certDetails CertDetail
	d.Where(&CertDetail{Domain: domain}).First(&certDetails)
	certDetails.Value = s
	d.Save(&certDetails)
	return err
}

package main

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/pkg/errors"
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

func db(dbHost string, dbPort string, dbUser string, dbName string, dbPassword string, dbSslMode string) *gorm.DB {
	conn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=%s", dbHost, dbPort, dbUser, dbName, dbPassword, dbSslMode)
	db, err := gorm.Open("postgres", conn)
	if err != nil {
		fmt.Println(err)
		panic("failed to connect to certManager database")
	}
	return db
}

/**
Get Domain AltNames via domain
*/
func getAltNames(domain string, d *gorm.DB) (altNamesRaw []byte, err error) {
	var altNames DomainAltname
	if dbErr := d.Where(&DomainAltname{Domain: domain}).First(&altNames); dbErr != nil {
		return altNamesRaw, errors.Wrapf(err, "GORM error %s", dbErr)
	}
	altNamesRaw = []byte(altNames.Value)
	return altNamesRaw, err
}

/**
Get User Info via email
*/
func getUserInfo(email string, d *gorm.DB) (userInfoRaw []byte, err error) {
	var userInfo UserInfo
	if dbErr := d.Where(&UserInfo{Email: email}).Find(&userInfo); dbErr != nil {
		return userInfoRaw, errors.Wrapf(err, "GORM error %s", dbErr)
	}
	userInfoRaw = []byte(userInfo.Value)
	return userInfoRaw, err
}

/**
Get Certificate Details via Domain
*/
func getCertDetails(domain string, d *gorm.DB) (certDetailsRaw []byte, err error) {
	var certDetails CertDetail
	if dbErr := d.Where(&CertDetail{Domain: domain}).First(&certDetails); dbErr != nil {
		return certDetailsRaw, errors.Wrapf(err, "GORM error %s", dbErr)
	}
	certDetailsRaw = []byte(certDetails.Value)
	return certDetailsRaw, err
}

/**
Save User Information key email, value userInfo
*/
func addUserInfo(email string, userInfo []byte, d *gorm.DB) (err error) {
	s := string(userInfo)
	if dbErr := d.Create(&UserInfo{Email: email, Value: s}); dbErr != nil {
		return errors.Wrapf(err, "GORM error %s", dbErr)
	}
	return err
}

/**
Save Certificate Details key domain, value certDetails
*/
func addCertDetails(domain string, certDetails []byte, d *gorm.DB) (err error) {
	s := string(certDetails)
	if dbErr := d.Create(&CertDetail{Domain: domain, Value: s}); dbErr != nil {
		return errors.Wrapf(err, "GORM error %s", dbErr)
	}
	return err
}

/**
Save Alt Names Details key domain, value altNames
*/
func addAltNames(domain string, altNames []byte, d *gorm.DB) (err error) {
	s := string(altNames)
	if dbErr := d.Create(&DomainAltname{Domain: domain, Value: s}); dbErr != nil {
		return errors.Wrapf(err, "GORM error %s", dbErr)
	}
	return err
}

/**
Update Alt Names Details key domain, new values altNames
*/
func updateAltNames(domain string, altNamesRaw []byte, d *gorm.DB) (err error) {
	s := string(altNamesRaw)
	var altNames DomainAltname
	if dbErr := d.Where(&DomainAltname{Domain: domain}).First(&altNames); dbErr != nil {
		return errors.Wrapf(err, "GORM error %s", dbErr)
	}
	altNames.Value = s
	d.Save(&altNames)
	return err
}

/**
Update Certificate Details key domain, new value certDetails
*/
func updateCertDetails(domain string, certDetailsRaw []byte, d *gorm.DB) (err error) {
	s := string(certDetailsRaw)
	var certDetails CertDetail
	if dbErr := d.Where(&CertDetail{Domain: domain}).First(&certDetails); dbErr != nil {
		return errors.Wrapf(err, "GORM error %s", dbErr)
	}
	certDetails.Value = s
	d.Save(&certDetails)
	return err
}

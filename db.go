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
func getAltNames(domain string, d *gorm.DB) ([]byte, error) {
	var altNames DomainAltname
	var altNamesRaw []byte
	if d.Where(&DomainAltname{Domain: domain}).First(&altNames).RecordNotFound() {
		altNamesRaw = []byte(altNames.Value)
		return altNamesRaw, nil
	}
	altNamesRaw = []byte(altNames.Value)
	if dbErr := d.Where(&DomainAltname{Domain: domain}).First(&altNames).Error; dbErr != nil {
		return altNamesRaw, errors.Wrapf(dbErr, "Unable to get alternate domains for %s", domain)
	}
	altNamesRaw = []byte(altNames.Value)
	return altNamesRaw, nil
}

/**
Get User Info via email
*/
func getUserInfo(email string, d *gorm.DB) ([]byte, error) {
	var userInfo UserInfo
	var userInfoRaw []byte
	if d.Where(&UserInfo{Email: email}).Find(&userInfo).RecordNotFound() {
		userInfoRaw = []byte(userInfo.Value)
		return userInfoRaw, nil
	}
	if dbErr := d.Where(&UserInfo{Email: email}).Find(&userInfo).Error; dbErr != nil {
		return userInfoRaw, errors.Wrapf(dbErr, "Unable to get user info for %s", email)
	}
	userInfoRaw = []byte(userInfo.Value)
	return userInfoRaw, nil
}

/**
Get Certificate Details via Domain
*/
func getCertDetails(domain string, d *gorm.DB) ([]byte, error) {
	var certDetails CertDetail
	var certDetailsRaw []byte
	if d.Where(&CertDetail{Domain: domain}).First(&certDetails).RecordNotFound() {
		certDetailsRaw = []byte(certDetails.Value)
		return certDetailsRaw, nil
	}
	if dbErr := d.Where(&CertDetail{Domain: domain}).First(&certDetails).Error; dbErr != nil {
		return certDetailsRaw, errors.Wrapf(dbErr, "Unable to get certificate details for %s", domain)
	}
	certDetailsRaw = []byte(certDetails.Value)
	return certDetailsRaw, nil
}

/**
Save User Information key email, value userInfo
*/
func addUserInfo(email string, userInfo []byte, d *gorm.DB) error {
	s := string(userInfo)
	if dbErr := d.Create(&UserInfo{Email: email, Value: s}).Error; dbErr != nil {
		return errors.Wrapf(dbErr, "Unable to add user info for %s", email)
	}
	return nil
}

/**
Save Certificate Details key domain, value certDetails
*/
func addCertDetails(domain string, certDetails []byte, d *gorm.DB) error {
	s := string(certDetails)
	if dbErr := d.Create(&CertDetail{Domain: domain, Value: s}).Error; dbErr != nil {
		return errors.Wrapf(dbErr, "Unable to add cert details for %s", domain)
	}
	return nil
}

/**
Save Alt Names Details key domain, value altNames
*/
func addAltNames(domain string, altNames []byte, d *gorm.DB) error {
	s := string(altNames)
	if dbErr := d.Create(&DomainAltname{Domain: domain, Value: s}).Error; dbErr != nil {
		return errors.Wrapf(dbErr, "Unable to add alt names for %s", domain)
	}
	return nil
}

/**
Update Alt Names Details key domain, new values altNames
*/
func updateAltNames(domain string, altNamesRaw []byte, d *gorm.DB) error {
	s := string(altNamesRaw)
	var altNames DomainAltname
	if dbErr := d.Where(&DomainAltname{Domain: domain}).First(&altNames).Error; dbErr != nil {
		return errors.Wrapf(dbErr, "On update, unable to retrieve alt names for %s", domain)
	}
	altNames.Value = s
	if dbErr := d.Save(&altNames).Error; dbErr != nil {
		return errors.Wrapf(dbErr, "Unable to update alt names for %s", domain)
	}
	return nil
}

/**
Update Certificate Details key domain, new value certDetails
*/
func updateCertDetails(domain string, certDetailsRaw []byte, d *gorm.DB) error {
	s := string(certDetailsRaw)
	var certDetails CertDetail
	if dbErr := d.Where(&CertDetail{Domain: domain}).First(&certDetails).Error; dbErr != nil {
		return errors.Wrapf(dbErr, "On update, unable to retrieve cert details for %s", domain)
	}
	certDetails.Value = s
	if dbErr := d.Save(&certDetails).Error; dbErr != nil {
		return errors.Wrapf(dbErr, "Unable to update cert details for %s", domain)
	}
	return nil
}

/**
Wrapper function to either save or update depending on renewal flag
*/
func saveCertDetails(domain string, certDetailsRaw []byte, d *gorm.DB, isRenewal bool) error {
	if isRenewal {
		return updateCertDetails(domain, certDetailsRaw, d)
	} else {
		return addCertDetails(domain, certDetailsRaw, d)
	}
}

/**
Wrapper function to either save or update depending on renewal flag
*/
func saveAltNames(domain string, altNamesRaw []byte, d *gorm.DB, isRenewal bool) error {
	if isRenewal {
		return updateAltNames(domain, altNamesRaw, d)
	} else {
		return addAltNames(domain, altNamesRaw, d)
	}
}

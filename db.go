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
Save Certificate Details
*/
func saveCertDetails(domain string, certDetailsRaw []byte, db *gorm.DB) error {
	var certDetails CertDetail

	err := db.Where(CertDetail{Domain: domain}).Assign(CertDetail{Value: string(certDetailsRaw)}).FirstOrCreate(&certDetails).Error
	if err != nil {
		return errors.Wrapf(err, "Unable to save cert details for %s", domain)
	}

	return nil
}

/**
Save Alternative Names
*/
func saveAltNames(domain string, altNamesRaw []byte, db *gorm.DB) error {
	var altNames DomainAltname

	err := db.Where(DomainAltname{Domain: domain}).Assign(DomainAltname{Value: string(altNamesRaw)}).FirstOrCreate(&altNames).Error
	if err != nil {
		return errors.Wrapf(err, "Unable to save alt names for %s", domain)
	}

	return nil
}

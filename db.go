package main

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
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
	fmt.Println("Calling to connect to DATABASE!!!!!")
	db, err := gorm.Open("postgres", "host=localhost port=5432 user=certmanager dbname=certmanager password=Pass1234 sslmode=disable")
	if err != nil {
		fmt.Println(err)
		panic("failed to connect to certManager database")
	}

	return db, err
	//defer db.Close()
}

/**
Get Domain AltNames via domain
*/
func getAltNames(domain string) (altNames []byte, err error) {
	fmt.Println("Callng the get AltNames function")
	fmt.Println(domain)
	d, err := db()
	if err != nil {
		fmt.Println(err)
	}

	d.Where(&DomainAltname{Domain: domain}).First(&altNames)
	defer d.Close()
	return altNames, err
}

/**
Get User Info via email
*/
func getUserInfo(email string) (userInfo []byte, err error) {
	fmt.Println("Calling the get UserInfo function")
	fmt.Println(email)
	d, err := db()
	if err != nil {
		fmt.Println(err)
	}

	d.Where(&UserInfo{Email: email}).First(&userInfo)
	defer d.Close()
	return userInfo, err
}

/**
Get Certificate Details via Domain
*/
func getCertDeatils(domain string) (certDetails []byte, err error) {
	fmt.Println("Calling the get cert Details function")
	fmt.Println(domain)
	d, err := db()
	if err != nil {
		fmt.Println(err)
	}

	d.Where(&CertDetail{Domain: domain}).First(&certDetails)
	defer d.Close()
	return certDetails, err
}

/**
Save User Information key email, value userInfo
*/
func addUserInfo(email string, userInfo []byte) error {
	fmt.Println("Calling the add user info function")
	fmt.Println(email)

	d, err := db()
	if err != nil {
		fmt.Println(err)
	}

	s := string(userInfo)
	fmt.Println(s)
	d.Create(&UserInfo{Email: email, Value: s})
	defer d.Close()
	return err
}

/**
Save Certificate Details key domain, value certDetails
*/
func addCertDetails(domain string, certDetails []byte) error {
	fmt.Println("Calling the add certDetails function")
	fmt.Println(domain)
	d, err := db()
	if err != nil {
		fmt.Println(err)
	}

	s := string(certDetails)
	fmt.Println(s)
	d.Create(&CertDetail{Domain: domain, Value: s})
	defer d.Close()
	return err
}

/**
Save Alt Name Details key domain, value altNames
*/
func addAltNames(domain string, altNames []byte) error {
	fmt.Println("Calling the add alt name function")
	fmt.Println(domain)
	d, err := db()
	if err != nil {
		fmt.Println(err)
	}

	s := string(altNames)
	fmt.Println(s)
	d.Create(&DomainAltname{Domain: domain, Value: s})
	defer d.Close()
	return err
}

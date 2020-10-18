package main

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func dbConn() (db *gorm.DB) {
	db, err := gorm.Open(mysql.Open("root:root@tcp(127.0.0.1:3306)/sni"), &gorm.Config{})
	if err != nil {
		panic(err.Error())
	}
	return db
}

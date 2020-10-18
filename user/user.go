package user

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID           uint `gorm:"primary_key,auto_increment"`
	Username     string
	FirstName    string
	LastName     string
	PasswordHash string
	Type         uint8
}

type NotExistsError struct {
}

func (*NotExistsError) Error() string {
	return "User does not exist"
}

func Login(db *gorm.DB, username string, password string) (*User, error) {
	byUsername, err := GetByUsername(db, username)
	if err != nil {
		return nil, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(byUsername.PasswordHash), []byte(password))
	if err != nil {
		return nil, err
	}
	return byUsername, nil
}

func GetUser(db *gorm.DB, id uint) (*User, error) {
	var u User
	res := db.Find(&u, id)
	if res.Error != nil {
		return nil, &NotExistsError{}
	}
	return &u, res.Error
}
func GetByUsername(db *gorm.DB, username string) (*User, error) {
	var u User
	res := db.Find(&u, "username = ?", username)
	if res.Error != nil {
		return nil, &NotExistsError{}
	}
	return &u, res.Error
}

func GetAllUsers(db *gorm.DB) ([]User, error) {
	var u []User
	res := db.Find(&u)
	if res.Error != nil {
		return nil, res.Error
	}
	return u, nil
}

func Create(db *gorm.DB, user *User) (uint, error) {
	err := db.Create(user).Error
	if err != nil {
		return 0, err
	}
	return user.ID, nil
}
func Update(db *gorm.DB, user *User) (uint, error) {
	err := db.Model(&user).Updates(User{
		ID:           user.ID,
		Username:     user.Username,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		PasswordHash: user.PasswordHash,
		Type:         user.Type,
	}).Error
	if err != nil {
		return 0, err
	}
	return user.ID, nil
}
func Delete(db *gorm.DB, user *User) (uint, error) {
	err := db.Delete(&user).Error
	if err != nil {
		return 0, err
	}
	return user.ID, nil
}

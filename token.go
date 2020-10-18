package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"sni-admin/user"
	"strconv"
	"time"
)

const (
	mySigningKey = "WOW,MuchShibe,NewDogge"
	myRefreshKey = "WOW,MuchShibe,AgainDogge"
)

type TokenDetails struct {
	UserID       uint
	AccessToken  string
	RefreshToken string
	AtExpires    int64
	RtExpires    int64
}

func CreateToken(u user.User) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.UserID = u.ID
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.RtExpires = time.Now().Add(time.Hour * 1).Unix()

	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = u.ID
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(mySigningKey))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	atClaims["user_id"] = u.ID
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(myRefreshKey))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func CreateAuth(r *http.Request, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	now := time.Now()

	errAccess := red.Set(ctx, r.RemoteAddr, td, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	return nil
}

func ExtractToken(r *http.Request) string {
	bearToken, err := r.Cookie("sni")
	if err != nil {
		return ""
	}
	//normally Authorization the_token_xxx
	return bearToken.Value
}
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(mySigningKey), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

type AccessDetails struct {
	UserId uint64
}

func ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			UserId: userId,
		}, nil
	}
	return nil, err
}

func (td *TokenDetails) MarshalBinary() ([]byte, error) {
	return json.Marshal(td)
}

type CookieMismatchError struct {
}

func (e *CookieMismatchError) Error() string {
	return "cookie and redis token mismatch"
}
func IsLoggedIn(r *http.Request) (*user.User, error) {
	a, err := ExtractTokenMetadata(r)
	if err != nil {
		return nil, err
	}
	td, err := red.Get(ctx, r.RemoteAddr).Result()
	if err != nil {
		return nil, err
	}
	var tdd TokenDetails
	err = json.Unmarshal([]byte(td), &tdd)
	if err != nil {
		return nil, err
	}
	if tdd.UserID != uint(a.UserId) {
		Logout(r)
		return nil, &CookieMismatchError{}
	}
	u, err := user.GetUser(db, uint(a.UserId))
	if err != nil {
		return nil, err
	}
	return u, nil
}
func Logout(r *http.Request) {
	red.Del(ctx, r.RemoteAddr)
}

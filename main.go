package sni_admin

import (
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"html/template"
	"log"
	"net/http"
	"sni-admin/user"
	"strconv"
)

func GetUserType(req *http.Request) int {
	il, err := IsLoggedIn(req)
	if err != nil {
		return -1
	}
	return int(il.Type)
}

func indexPageHandler(res http.ResponseWriter, req *http.Request) {
	http.ServeFile(res, req, "./static/index.html")
}
func loginPageHandler(res http.ResponseWriter, req *http.Request) {
	a := GetUserType(req)
	switch a {
	case 2:
		http.Redirect(res, req, "https://localhost/shop", http.StatusSeeOther)
		return
	case 1:
		http.Redirect(res, req, "https://localhost/management", http.StatusSeeOther)
		return
	case 0:
		http.Redirect(res, req, "https://localhost/admin/users", http.StatusSeeOther)
		return
	case -1:
		if req.Method == "GET" {
			http.ServeFile(res, req, "./static/login.html")
		} else if req.Method == "POST" {
			un := template.HTMLEscapeString(req.FormValue("username"))
			pw := template.HTMLEscapeString(req.FormValue("password"))
			u, err := user.Login(db, un, pw)
			if err != nil {
				http.Redirect(res, req, "https://localhost/admin/home", http.StatusSeeOther)
			} else {
				token, _ := CreateToken(*u)
				_ = CreateAuth(req, token)
				cookie := &http.Cookie{Name: "sni", Value: token.AccessToken, HttpOnly: false}
				http.SetCookie(res, cookie)
				if u.Type == 0 {
					http.Redirect(res, req, "https://localhost/admin/users", http.StatusSeeOther)
				} else if u.Type == 1 {
					http.Redirect(res, req, "https://localhost/management", http.StatusSeeOther)
				} else if u.Type == 2 {
					http.Redirect(res, req, "https://localhost/shop", http.StatusSeeOther)
				}
			}
		}
	}
}

func usersHandler(res http.ResponseWriter, req *http.Request) {
	if GetUserType(req) != 0 {
		http.Redirect(res, req, "https://localhost/admin/users", http.StatusForbidden)
	} else {
		Users, _ := user.GetAllUsers(db)
		t, _ := template.ParseFiles("./static/users.html")
		if req.Method == "GET" {
			_ = t.Execute(res, Users)
		} else if req.Method == "POST" {
			un := template.HTMLEscapeString(req.FormValue("username"))
			fn := template.HTMLEscapeString(req.FormValue("firstname"))
			ln := template.HTMLEscapeString(req.FormValue("lastname"))
			pw := template.HTMLEscapeString(req.FormValue("password"))
			typ, _ := strconv.Atoi(template.HTMLEscapeString(req.FormValue("type")))
			ph, _ := bcrypt.GenerateFromPassword([]byte(pw), 14)
			if un != "" && fn != "" && ln != "" && pw != "" {
				_, err := user.Create(db, &user.User{Username: un, FirstName: fn, LastName: ln, PasswordHash: string(ph), Type: uint8(typ)})
				if err != nil {
					panic(err.Error())
				}
				Users, _ = user.GetAllUsers(db)
				_ = t.Execute(res, Users)
			} else {
				http.Redirect(res, req, "https://localhost/admin/users", http.StatusSeeOther)
			}
		}
	}
}

func userHandler(res http.ResponseWriter, req *http.Request) {
	if GetUserType(req) != 0 {
		http.Redirect(res, req, "https://localhost/admin/users", http.StatusForbidden)
	} else {
		id, _ := strconv.Atoi(mux.Vars(req)["id"])
		u, _ := user.GetUser(db, uint(id))
		t, _ := template.ParseFiles("./static/user.html")
		if req.Method == "GET" {
			_ = t.Execute(res, u)
		} else if req.Method == "POST" {
			un := template.HTMLEscapeString(req.FormValue("username"))
			fn := template.HTMLEscapeString(req.FormValue("firstname"))
			ln := template.HTMLEscapeString(req.FormValue("lastname"))
			pw := template.HTMLEscapeString(req.FormValue("password"))
			typ, _ := strconv.Atoi(template.HTMLEscapeString(req.FormValue("type")))
			ty := uint8(typ)
			log.Println(ty)
			if un != "" && un != u.Username {
				u.Username = un
			}
			if fn != "" && fn != u.FirstName {
				u.FirstName = fn
			}
			if ln != "" && ln != u.LastName {
				u.LastName = ln
			}
			if pw != "" {
				ph, _ := bcrypt.GenerateFromPassword([]byte(pw), 14)
				u.PasswordHash = string(ph)
			}
			if ty != u.Type {
				u.Type = ty
			}
			_, _ = user.Update(db, u)
			http.Redirect(res, req, "https://localhost/admin/users", http.StatusSeeOther)
		}
	}
}

var red *redis.Client
var db *gorm.DB

func main() {

	db = dbConn()
	red = getRedisClient()
	//user.Create(db, &user.User{ID: 1, Username: "admin", FirstName: "admin", LastName: "admin", PasswordHash: "$2a$14$ItP/ABjqa5iSr0j1rJMwDOTKEPTxIH3ahi/6o2Teeuv87PG29t.UC", Type: 2})
	router := mux.NewRouter()
	router.HandleFunc("/", indexPageHandler).Name("home")
	router.HandleFunc("/admin", indexPageHandler).Name("home")
	router.HandleFunc("/home", indexPageHandler).Name("home")
	router.HandleFunc("/index", indexPageHandler).Name("home")
	router.HandleFunc("/login", loginPageHandler).Name("login")
	router.HandleFunc("/users", usersHandler).Name("users")
	router.HandleFunc("/users/{id:[0-9]+}", userHandler).Name("user")

	log.Println("Listening on :3000")
	err := http.ListenAndServe(":3000", router)
	if err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
)

type Post struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Date    string `json:"date"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Video struct {
	Title string `json:"title"`
	URL   string `json:"url"`
	Image string `json:"image"`
}

type PageData struct {
	Posts  map[string][]Post
	Videos map[string][]Video
	IsAuth bool
}

const PostFileName = "data/posts_data.json"
const UserFileName = "data/users_data.json"
const VideoFileName = "data/videos_data.json"

var store = sessions.NewCookieStore([]byte("super-secret-key-underscore-very-long-naughty-secret"))

func main() {
	posts, err := LoadPostData()
	if err != nil {
		log.Fatalf("[!] Error loading data: %s", err)
		posts = make(map[string][]Post)
		posts["Posts"] = []Post{}
	}

	users, err := LoadUserData()
	if err != nil {
		log.Fatalf("[!] Error loading data: %s", err)
		users = make(map[string][]User)
		users["Users"] = []User{}
	}

	videos, err := VideoLoadData()
	if err != nil {
		log.Fatalf("[!] Error loading data: %s", err)
		videos = make(map[string][]Video)
		videos["Videos"] = []Video{}
	}

	log.Println("[*] Server started at port 42069..........")

	templ := func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		auth, ok := session.Values["authenticated"].(bool)
		if !ok {
			auth = false
		}

		data := PageData{
			Posts:  posts,
			IsAuth: auth,
			Videos: videos,
		}

		tmpl := template.Must(template.ParseFiles("index.html"))
		_ = tmpl.Execute(w, data)
	}

	login := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := r.PostFormValue("username")
		password := r.PostFormValue("password")

		if username == "" || password == "" {
			http.Error(w, "missing fields", http.StatusBadRequest)
			return

		}

		var userFound bool
		for _, user := range users["Users"] {
			if user.Username == username && user.Password == password {
				userFound = true
				break
			}
		}

		if userFound {
			session, err := store.Get(r, "auth-session")
			if err != nil {
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			session.Values["authenticated"] = true
			session.Values["username"] = username
			if err := session.Save(r, w); err != nil {
				http.Error(w, "Failed to save session", http.StatusInternalServerError)
				return
			}

			w.Header().Set("HX-Redirect", "/")
			w.WriteHeader(http.StatusCreated)

		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}

	}

	signup := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := r.PostFormValue("username")
		password := r.PostFormValue("password")

		if username == "" || password == "" {
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}

		NewUser := User{
			Username: username,
			Password: password,
		}

		users["Users"] = append(users["Users"], NewUser)

		if err := SaveUserData(users); err != nil {
			log.Printf("[!] Error saving data: %s", err)
			http.Error(w, "failed to save data", http.StatusInternalServerError)

			users["Users"] = users["Users"][:len(users["Users"])-1]
			return
		}
		w.Header().Set("HX-Redirect", "/login.html")
		w.WriteHeader(http.StatusCreated)

	}

	logout := func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		session.Options.MaxAge = -1

		if err := session.Save(r, w); err != nil {
			http.Error(w, "Failed to destroy session", http.StatusInternalServerError)
			return
		}

		w.Header().Set("HX-Redirect", "/login.html")
		w.WriteHeader(http.StatusSeeOther)
	}

	postsTempl := func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		auth, ok := session.Values["authenticated"].(bool)
		if !ok {
			auth = false
		}

		data := PageData{
			Posts:  posts,
			IsAuth: auth,
			Videos: videos,
		}
		tmpl := template.Must(template.ParseFiles("view/posts.html"))
		_ = tmpl.Execute(w, data)
	}

	createPosts := func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		auth, ok := session.Values["authenticated"].(bool)
		if !ok {
			auth = false
		}

		data := PageData{
			Posts:  posts,
			IsAuth: auth,
			Videos: videos,
		}
		tmpl := template.Must(template.ParseFiles("view/create-posts.html"))
		_ = tmpl.Execute(w, data)
	}
	addPosts := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		title := r.PostFormValue("post-title")
		content := r.PostFormValue("post-content")
		date := time.Now().Format("2006-01-02")

		if title == "" || content == "" || date == "" {
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}

		NewPost := Post{
			Title:   title,
			Content: content,
			Date:    date,
		}

		posts["Posts"] = append(posts["Posts"], NewPost)

		if err := SavePostData(posts); err != nil {
			log.Printf("[!] Error saving data: %s", err)
			http.Error(w, "failed to save data", http.StatusInternalServerError)

			posts["Posts"] = posts["Posts"][:len(posts["Posts"])-1]
			return
		}
		w.Header().Set("HX-Redirect", "/posts.html")
		w.WriteHeader(http.StatusCreated)

	}

	vidoesTempl := func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		auth, ok := session.Values["authenticated"].(bool)
		if !ok {
			auth = false
		}

		data := PageData{
			Posts:  posts,
			IsAuth: auth,
			Videos: videos,
		}
		tmpl := template.Must(template.ParseFiles("view/videos.html"))
		_ = tmpl.Execute(w, data)
	}

	createVideos := func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		auth, ok := session.Values["authenticated"].(bool)
		if !ok {
			auth = false
		}

		data := PageData{
			Posts:  posts,
			IsAuth: auth,
			Videos: videos,
		}
		tmpl := template.Must(template.ParseFiles("view/create-videos.html"))
		_ = tmpl.Execute(w, data)
	}

	addVideos := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		title := r.PostFormValue("video-title")
		url := r.PostFormValue("url")
		image := r.PostFormValue("image")

		if title == "" || url == "" || image == "" {
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}

		NewVideo := Video{
			Title: title,
			URL:   url,
			Image: image,
		}

		videos["Videos"] = append(videos["Videos"], NewVideo)

		if err := SaveVideoData(videos); err != nil {
			log.Printf("[!] Error saving data: %s", err)
			http.Error(w, "failed to save data", http.StatusInternalServerError)

			videos["Videos"] = videos["Videos"][:len(videos["Videos"])-1]
			return
		}
		w.Header().Set("HX-Redirect", "/videos.html")
		w.WriteHeader(http.StatusCreated)

	}

	loginPage := func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles("view/login.html"))
		_ = tmpl.Execute(w, nil)
	}

	signupPage := func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles("view/register.html"))
		_ = tmpl.Execute(w, nil)
	}


	http.Handle("/posts.html", authMiddleware(http.HandlerFunc(postsTempl)))
	http.Handle("/create-posts.html", authMiddleware(http.HandlerFunc(createPosts)))
	http.Handle("/create-posts/", authMiddleware(http.HandlerFunc(addPosts)))
	http.Handle("/videos.html", authMiddleware(http.HandlerFunc(vidoesTempl)))
	http.Handle("/create-videos.html", authMiddleware(http.HandlerFunc(createVideos)))
	http.Handle("/create-videos/", authMiddleware(http.HandlerFunc(addVideos)))

	http.HandleFunc("/", templ)
	http.HandleFunc("/login.html", loginPage)
	http.HandleFunc("/register.html", signupPage)
	http.HandleFunc("/login/", login)
	http.HandleFunc("/logout/", logout)
	http.HandleFunc("/signup/", signup)

	log.Fatal(http.ListenAndServe(":42069", nil))
}

func SaveUserData(users map[string][]User) error {

	userData, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling data: %s", err)
	}

	err = os.WriteFile(UserFileName, userData, 0644)
	if err != nil {
		return fmt.Errorf("failed writing file: %s", err)
	}

	return nil
}

func SavePostData(posts map[string][]Post) error {

	postData, err := json.MarshalIndent(posts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling data: %s", err)
	}

	err = os.WriteFile(PostFileName, postData, 0644)
	if err != nil {
		return fmt.Errorf("failed writing file: %s", err)
	}

	return nil
}

func SaveVideoData(videos map[string][]Video) error {

	videoData, err := json.MarshalIndent(videos, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling data: %s", err)
	}

	err = os.WriteFile(VideoFileName, videoData, 0644)
	if err != nil {
		return fmt.Errorf("failed writing file: %s", err)
	}

	return nil
}

func LoadUserData() (map[string][]User, error) {
	var Users map[string][]User

	jsonUserData, err := os.ReadFile(UserFileName)
	if err != nil {
		return nil, fmt.Errorf("failed reading file: %s", err)
	}

	if len(jsonUserData) == 0 {
		return make(map[string][]User), nil
	}

	err = json.Unmarshal(jsonUserData, &Users)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling data: %s", err)
	}

	return Users, nil
}

func LoadPostData() (map[string][]Post, error) {
	var Posts map[string][]Post

	jsonPostData, err := os.ReadFile(PostFileName)
	if err != nil {
		return nil, fmt.Errorf("failed reading file: %s", err)
	}

	if len(jsonPostData) == 0 {
		return make(map[string][]Post), nil
	}

	err = json.Unmarshal(jsonPostData, &Posts)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling data: %s", err)
	}

	log.Println("[*] Data loaded successfully.....")

	return Posts, nil
}

func VideoLoadData() (map[string][]Video, error) {
	var Videos map[string][]Video

	jsonVideoData, err := os.ReadFile(VideoFileName)
	if err != nil {
		return nil, fmt.Errorf("failed reading file: %s", err)
	}

	if len(jsonVideoData) == 0 {
		return make(map[string][]Video), nil
	}

	err = json.Unmarshal(jsonVideoData, &Videos)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling data: %s", err)
	}

	return Videos, nil
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		authStatus, ok := session.Values["authenticated"].(bool)
		if !ok || !authStatus {
			w.Header().Set("HX-Redirect", "/login.html")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

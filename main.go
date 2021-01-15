package main

import "fmt"
import "net/http"
import "encoding/json"
import "io/ioutil"
import "database/sql"
import _ "github.com/lib/pq"
import "html/template"
import "regexp"
import "strings"
import "strconv"
import "math"
import "sort"
import "mime/multipart"
import "bytes"
import "io"
import "time"
import "bufio"

import "os"
import "os/exec"
import "math/rand"

import "github.com/gomodule/redigo/redis"
import "github.com/satori/go.uuid"

//The main instance that client is talking to
var Domain = GetConfigValue("instance")

//The client that the server is talking to
var LocalDomain = GetConfigValue("client")

//client port
var Port = ":" + GetConfigValue("clientport")

var TP = GetInstanceTP(Domain)

var Key *string = new(string)

var Boards *[]ObjectBase = new([]ObjectBase)

type Board struct{
	Name string
	Actor string
	Summary string
	PrefName string
	InReplyTo string
	Location string
	To string
	RedirectTo string
	Captcha string
	CaptchaCode string
	IsMod bool
	TP string
}

type PageData struct {
	Title string
	Board Board
	Pages []int
	CurrentPage int
	TotalPage int
	Boards []Board
	Posts []ObjectBase
	Key string
}

type AdminPage struct {
	Title string
	Board Board
	Key string
	Actor string
	Boards []Board	
	Following []string
	Followers []string
	Reported []Report
	Domain string
}

type Report struct {
	ID string
	Count int
}

type Verify struct {
	Type string
	Identifier string
	Code string
	Created string
	Board string
}

var cache redis.Conn

func initCache() {
	conn, err := redis.DialURL("redis://localhost")
	if err != nil {
		panic(err)
	}
	cache = conn
}

func checkSession(w http.ResponseWriter, r *http.Request) (interface{}, error){

	c, err := r.Cookie("session_token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return nil, err
		}
		
		w.WriteHeader(http.StatusBadRequest)
		return nil, err
	}
	
	sessionToken := c.Value

	response, err := cache.Do("GET", sessionToken)
	
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return nil, err
	}
	if response == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, err
	}

	return response, nil
}

func main() {

	if _, err := os.Stat("./public"); os.IsNotExist(err) {
    os.Mkdir("./public", 0755)
	}

	initCache()

	CreateClientKey()

	*Key = GetClientKey()

	db := ConnectDB();

	defer db.Close()

	actor := GetActor(Domain)

	items := GetActorCollection(actor.Following).Items
	Boards = &items

	// Allow access to public media folder
	fileServer := http.FileServer(http.Dir("./public"))
	http.Handle("/public/", http.StripPrefix("/public", neuter(fileServer)))

	javascriptFiles := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static", neuter(javascriptFiles)))				

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request){
		path := r.URL.Path
		actor := GetActorFromPath(path, "/")

		index := (path == "/")
		
		all := (path == "/" + actor) || (path == "/" + actor + "/")

		re := regexp.MustCompile("/" + actor + "/\\w+")
		
		post := 	re.MatchString(path)

		re = regexp.MustCompile("/" + actor + "/[0-9]{1,2}$")
		
		page := re.MatchString(path)		
		
		catalog := (path == "/" + actor + "/catalog")

		if index {
			IndexGet(w,  r)
		} else if all {
			collection, valid := WantToServe(actor)
			if valid {
				OutboxGet(w, r, db, collection)
			} else {
				
			}
		} else if catalog {
			CatalogGet(w, r, db)
		} else if page {
			collection, valid := WantToServe(actor)
			if valid {
				OutboxGet(w, r, db, collection)
			} else {

			}
		} else if post {
			PostGet(w, r, db)
		} else {

		}
	})

	http.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request){

		r.ParseMultipartForm(10 << 20)

		file, header, _ := r.FormFile("file")

		if(file != nil && header.Size > (7 << 20)){
			w.Write([]byte("7MB max file size"))
			return
		}

		if(r.FormValue("comment") == "" && r.FormValue("subject") == ""){
			w.Write([]byte("Comment or Subject required"))
			return
		}

		if(r.FormValue("captcha") == "") {
			w.Write([]byte("Captcha required"))
			return
		}			
		
		b := bytes.Buffer{}
		we := multipart.NewWriter(&b)

		if(file != nil){
			var fw io.Writer
			
			fw, err := we.CreateFormFile("file", header.Filename)

			CheckError(err, "error with form file create")

			_, err = io.Copy(fw, file)
			
			CheckError(err, "error with form file copy")
		}

		reply := ParseCommentForReply(r.FormValue("comment"))

		for key, r0 := range r.Form {
			if(key == "captcha") {
				err := we.WriteField(key, r.FormValue("captchaCode") + ":" + r.FormValue("captcha"))
				CheckError(err, "error with writing field")					
			}else{
				err := we.WriteField(key, r0[0])
				CheckError(err, "error with writing field")
			}
		}
		
		if(r.FormValue("inReplyTo") == "" && reply != ""){
			err := we.WriteField("inReplyTo", reply)
			CheckError(err, "error with writing inReplyTo field")			
		}
		
		we.Close()

		req, err := http.NewRequest("POST", r.FormValue("sendTo"), &b)
		
		CheckError(err, "error with post form req")
		
		req.Header.Set("Content-Type", we.FormDataContentType())
		req.Header.Set("Authorization", "api:" + *Key)		

		resp, err := http.DefaultClient.Do(req)

		var nObj ObjectBase

		nObj = ParseOptions(r, nObj)

		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)

		CheckError(err, "error with post form resp")
		if(resp.StatusCode == 200){
			var obj ObjectBase
			obj = ParseOptions(r, obj)
			for _, e := range obj.Option {
				if(e == "noko" || e == "nokosage"){
					http.Redirect(w, r, TP + "" + LocalDomain + "/" + r.FormValue("boardName") + "/" + string(body) , http.StatusMovedPermanently)
					break
				}
			}
			http.Redirect(w, r, TP + "" + LocalDomain + "/" + r.FormValue("boardName"), http.StatusMovedPermanently)			
		}
	})	

	http.HandleFunc("/" + *Key + "/", func(w http.ResponseWriter, r *http.Request) {


		id, _ := GetPasswordFromSession(r)
		
		name := GetActorFromPath(r.URL.Path, "/" + *Key + "/")
		actor := GetActorByName(name)

		if actor.Name == "" {
			actor.Id = name
			actor.Outbox = Domain + "/outbox"
		}

		if id != StripTransferProtocol(actor.Id) && id != Domain {
			t := template.Must(template.ParseFiles("./static/verify.html"))
			t.Execute(w, "")
			return
		}

		re := regexp.MustCompile("/" + *Key + "/" + actor.Name + "/follow")
		follow := re.MatchString(r.URL.Path)

		re = regexp.MustCompile("/" + *Key + "/" + actor.Name)
		manage := re.MatchString(r.URL.Path)

		re = regexp.MustCompile("/" + *Key )
		admin := re.MatchString(r.URL.Path)

		re = regexp.MustCompile("/" + *Key + "/follow" )
		adminFollow := re.MatchString(r.URL.Path)		

		if follow || adminFollow {
			r.ParseForm()

			var followActivity Activity

			followActivity.AtContext.Context = "https://www.w3.org/ns/activitystreams"
			followActivity.Type = "Follow"
			followActivity.Actor.Id = r.FormValue("actor")
			followActivity.Object.Id = r.FormValue("follow")
			_, pass := GetPasswordFromSession(r)			
			followActivity.Auth = pass

			enc, _ := json.Marshal(followActivity)

			_, _ = http.Post(actor.Outbox , "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"", bytes.NewReader(enc))

			http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
			
		} else if manage && actor.Name != "" {
			t := template.Must(template.ParseFiles("./static/main.html", "./static/manage.html"))

			follow := GetActorCollection(actor.Following)
			follower := GetActorCollection(actor.Followers)
			reported := GetActorCollectionReq(r, actor.Id + "/reported")

			var following []string
			var followers []string
			var reports   []Report

			for _, e := range follow.Items {
				following = append(following, e.Id)
			}

			for _, e := range follower.Items {
				followers = append(followers, e.Id)
			}

			for _, e := range reported.Items {
				var r Report
				r.Count = int(e.Size)
				r.ID    = e.Id
				reports = append(reports, r)
			}

			localReports := GetLocalReportDB(db, actor.Name)

			for _, e := range localReports {
				var r Report
				r.Count = e.Count
				r.ID    = e.ID
				reports = append(reports, r)
			}			

			var adminData AdminPage
			adminData.Following = following
			adminData.Followers = followers
			adminData.Reported  = reports
			adminData.Domain = LocalDomain

			var boardCollection []Board

			boardCollection = GetBoardCollection()
			
			adminData.Title = "Manage /" + actor.Name + "/"
			adminData.Boards = boardCollection
			adminData.Board.Name = actor.Name
			adminData.Actor = actor.Id
			adminData.Key = *Key
			adminData.Board.TP = TP
			t.ExecuteTemplate(w, "layout", adminData)
			
		} else if admin || name == Domain {

			t := template.Must(template.ParseFiles("./static/main.html", "./static/nadmin.html"))						
			//t := template.Must(template.ParseFiles("./static/admin.html"))
	
			actor := GetActor(Domain)
			follow := GetActorCollection(actor.Following).Items
			follower := GetActorCollection(actor.Followers).Items

			var following []string
			var followers []string

			for _, e := range follow {
				following = append(following, e.Id)
			}

			for _, e := range follower {
				followers = append(followers, e.Id)
			}

			var adminData AdminPage
			adminData.Following = following
			adminData.Followers = followers
			adminData.Actor = actor.Id
			adminData.Key = *Key

			var boardCollection []Board

			boardCollection = GetBoardCollection()
			adminData.Boards = boardCollection			

			id, _ := GetPasswordFromSession(r)
			if Domain == id {
				adminData.Board.IsMod = true		
			} else {
				adminData.Board.IsMod = false				
			}							
			
			//			t.Execute(w, adminData)
			t.ExecuteTemplate(w, "layout",  adminData)				
		}
	})

	http.HandleFunc("/" + *Key + "/addboard", func(w http.ResponseWriter, r *http.Request) {

		var newActorActivity Activity
		var board Actor
		r.ParseForm()

		var restrict bool
		if r.FormValue("restricted") == "True" {
			restrict = true
		} else {
			restrict = false
		}
		
		board.Name = r.FormValue("name")
		board.PreferredUsername = r.FormValue("prefname")
		board.Summary = r.FormValue("summary")
		board.Restricted = restrict

		newActorActivity.AtContext.Context = "https://www.w3.org/ns/activitystreams"
		newActorActivity.Type = "New"
		newActorActivity.Actor.Id = actor.Id
		newActorActivity.Object.Actor = board
		_, pass := GetPasswordFromSession(r)					
		newActorActivity.Auth = pass

		enc, _ := json.Marshal(newActorActivity)

		actor := GetActor(Domain)

		resp, err := http.Post(actor.Outbox , "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"", bytes.NewReader(enc))

		CheckError(err, "error with add board follow resp")

		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)

		var respActor Actor
		
		err = json.Unmarshal(body, &respActor)

		CheckError(err, "error getting actor from body in new board")		

		//update board list with new instances following
		if resp.StatusCode == 200 {
			var board []ObjectBase
			var item ObjectBase			
			var removed bool = false

			item.Id = respActor.Id
			for _, e := range *Boards {
				if e.Id != item.Id {
					board = append(board, e)
				} else {
					removed = true
				}
			}

			if !removed {
				board = append(board, item)
			}
				
			*Boards = board
		}		

    http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)				
	})

	http.HandleFunc("/" + *Key + "/follow", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()		

		var followActivity Activity

		followActivity.AtContext.Context = "https://www.w3.org/ns/activitystreams"
		followActivity.Type = "Follow"
		followActivity.Actor.Id = r.FormValue("actor")
		followActivity.Object.Id = r.FormValue("follow")
			_, pass := GetPasswordFromSession(r)							
		followActivity.Auth = pass

		enc, _ := json.Marshal(followActivity)

		actor := GetActor(Domain)

		resp, err := http.Post(actor.Outbox , "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"", bytes.NewReader(enc))

		CheckError(err, "error with add board follow resp")

		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)

		var respActivity Activity

		err = json.Unmarshal(body, &respActivity)

		CheckError(err, "error getting follow activifty from body")


		//update board list with new instances following
		if resp.StatusCode == 200 {
			var board []ObjectBase
			var item ObjectBase			
			var removed bool = false

			item.Id = followActivity.Object.Id			
			for _, e := range *Boards {
				if e.Id != item.Id {
					board = append(board, e)
				} else {
					removed = true
				}
			}

			if !removed {
				board = append(board, item)
			}
				
			*Boards = board
		}

    http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)		
	})

	http.HandleFunc("/" + *Key + "/following", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()		

		var followActivity Activity

		followActivity.AtContext.Context = "https://www.w3.org/ns/activitystreams"
		followActivity.Type = "Follow"
		followActivity.Actor.Id = r.FormValue("actor")
		followActivity.Object.Id = r.FormValue("follow")
			_, pass := GetPasswordFromSession(r)									
		followActivity.Auth = pass

		enc, _ := json.Marshal(followActivity)

		actor := GetActor(Domain)

		_, err := http.Post(actor.Outbox , "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"", bytes.NewReader(enc))

		CheckError(err, "error with following resp")

    http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)		
	})	

	http.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		req, err := http.NewRequest("GET", TP + "" + Domain + "/delete?id=" + id, nil)

		CheckError(err, "error with deleting post")

			_, pass := GetPasswordFromSession(r)											

		req.Header.Set("Authorization", "Basic " + pass)		

		resp, err := http.DefaultClient.Do(req)

		CheckError(err, "error with getting delete post resp")

		if resp.StatusCode == 400 && pass != "" {
			CreateLocalDeleteDB(db, id, "post")
		}				
		
    http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
	})

	http.HandleFunc("/deleteattach", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		req, err := http.NewRequest("GET", TP + "" + Domain + "/deleteattach?id=" + id, nil)

		CheckError(err, "error with deleting attachment")

			_, pass := GetPasswordFromSession(r)													

		req.Header.Set("Authorization", "Basic " + pass)

		resp, err := http.DefaultClient.Do(req)

		CheckError(err, "error with getting delete attachment resp")

		if resp.StatusCode == 400 && pass != "" {
			CreateLocalDeleteDB(db, id, "attachment")			
		}		

    http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)		
	})

	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {

		id := r.URL.Query().Get("id")
		board := r.URL.Query().Get("board")
		close := r.URL.Query().Get("close")		

		req, err := http.NewRequest("GET", TP + "" + Domain + "/report?id=" + id + "&close=" + close, nil)

		CheckError(err, "error with reporting post")

		resp, err := http.DefaultClient.Do(req)

		CheckError(err, "error with getting reporting post resp")

		if resp.StatusCode == 400 {
			if close == "1" {
				CloseLocalReportDB(db, id, board)
			} else {
				CreateLocalReportDB(db, id, board)
			}
		}

    http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)				
	})

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request){
		if(r.Method == "POST") {
			r.ParseForm()
			identifier := r.FormValue("id")
			code := r.FormValue("code")

			var verify Verify
			verify.Identifier = identifier
			verify.Code = code

			j, _ := json.Marshal(&verify)
			
			req, err := http.NewRequest("POST", TP + "" + Domain + "/verify", bytes.NewBuffer(j))

			CheckError(err, "error making verify req")

			resp, err := http.DefaultClient.Do(req)

			CheckError(err, "error getting verify resp")

			defer resp.Body.Close()

			rBody, _ := ioutil.ReadAll(resp.Body)

			body := string(rBody)

			body = StripTransferProtocol(body)

			if(resp.StatusCode != 200) {
				t := template.Must(template.ParseFiles("./static/verify.html"))
				t.Execute(w, "wrong password " + verify.Code)			
			} else {
				
				sessionToken, _ := uuid.NewV4()

				_, err := cache.Do("SETEX", sessionToken, "86400", body + "|" + verify.Code)
				if err != nil {
					t := template.Must(template.ParseFiles("./static/verify.html"))
					t.Execute(w, "")			
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:    "session_token",
					Value:   sessionToken.String(),
					Expires: time.Now().Add(60 * 60 * 24 * time.Second),
				})

				http.Redirect(w, r, "/", http.StatusSeeOther)				
			}
		} else {
			t := template.Must(template.ParseFiles("./static/verify.html"))
			t.Execute(w, "")
		}
	})		

	fmt.Println("Client for " + Domain + " running on port " + Port)

	fmt.Println("Client key: " + *Key)
	
	http.ListenAndServe(Port, nil)
	
}

func ConnectDB() *sql.DB {

	host     := GetConfigValue("dbhost")
	port, _  := strconv.Atoi(GetConfigValue("dbport"))
	user     := GetConfigValue("dbuser")
	password := GetConfigValue("dbpass")
	dbname   := GetConfigValue("dbname")
	
	// connect to the database
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s " +
		"dbname=%s sslmode=disable", host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlInfo)
	CheckError(err, "error with db connection")

	err = db.Ping()

	CheckError(err, "error with db ping")

	fmt.Println("Successfully connected DB")
	return db
}

func CheckError(e error, m string) error{
	if e != nil {
		fmt.Println()
		fmt.Println(m)
		fmt.Println()		
		panic(e)
	}

	return e
}

func GetActor(id string) Actor {

	var respActor Actor

	id = StripTransferProtocol(id)

	req, err := http.NewRequest("GET", "http://" + id, nil)

	CheckError(err, "error with getting actor req")

	resp, err := http.DefaultClient.Do(req)

	CheckError(err, "error with getting actor resp")

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(body, &respActor)

	CheckError(err, "error getting actor from body")

	return respActor
}

func GetActorCollection(collection string) Collection {
	var nCollection Collection

	req, err := http.NewRequest("GET", collection, nil)

	CheckError(err, "error with getting actor collection req " + collection)

	resp, err := http.DefaultClient.Do(req)

	CheckError(err, "error with getting actor collection resp " + collection)

	if resp.StatusCode == 200 {

		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)

		err = json.Unmarshal(body, &nCollection)

		CheckError(err, "error getting actor collection from body " + collection)
	}
	
	return nCollection
}

func GetActorCollectionReq(r *http.Request, collection string) Collection {
	var nCollection Collection

	req, err := http.NewRequest("GET", collection, nil)

	CheckError(err, "error with getting actor collection req " + collection)

	_, pass := GetPasswordFromSession(r)													

	req.Header.Set("Authorization", "Basic " + pass)		

	resp, err := http.DefaultClient.Do(req)

	CheckError(err, "error with getting actor collection resp " + collection)

	if resp.StatusCode == 200 {

		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)

		err = json.Unmarshal(body, &nCollection)

		CheckError(err, "error getting actor collection from body " + collection)
	}
	
	return nCollection
}

func GetCollectiveOutbox(actor Actor) []ObjectBase {
	var cOutbox []ObjectBase

	actorFollowing := GetActorCollection(actor.Following).Items

	actorOutbox := GetActorCollection(actor.Outbox).OrderedItems

	for _, e := range actorOutbox {
		cOutbox = append(cOutbox, e)
	}
	
	for _, e := range actorFollowing {
		followingActor := GetActor(e.Id)
		followActorOutbox := GetActorCollection(followingActor.Outbox).OrderedItems

		for _, e := range followActorOutbox{
			cOutbox = append(cOutbox, e)
		}
	}

	return cOutbox
}

func IndexGet(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("./static/main.html", "./static/index.html"))

	actor := GetActor(Domain)

	type Board struct{
		Name string
		PrefName string
		InReplyTo string
		Location string
		IsMod bool
	}			
	
	type responseData struct {
		Title string
		Message string
		Boards []Board
		Board Board
		Key string
	}

	var boardCollection []Board

	for _, e := range *Boards {
		board := new(Board)		
		boardActor := GetActor(e.Id)
		board.Name = "/" + boardActor.Name + "/"
		board.PrefName = boardActor.PreferredUsername
		board.Location = "/" + boardActor.Name
		boardCollection = append(boardCollection, *board)
	}
	
	data := new(responseData)
	data.Title = "Welcome to " + actor.PreferredUsername
	data.Message = fmt.Sprintf("This is the client for the image board %s. The current version of the code running the server and client is volatile, expect a bumpy ride for the time being. Get the server and client code here https://github.com/FChannel0", Domain)
	data.Boards = boardCollection
	data.Board.Name = ""
	data.Key = *Key	

	id, _ := GetPasswordFromSession(r)

	if Domain == id {
		data.Board.IsMod = true		
	} else {
		data.Board.IsMod = false				
	}	
	
	t.ExecuteTemplate(w, "layout",  data)	
}

func GetActorFollowNameFromPath(path string) string{
	var actor string

	re := regexp.MustCompile("f\\w+-")

	actor = re.FindString(path)

	actor = strings.Replace(actor, "f", "", 1)
	actor = strings.Replace(actor, "-", "", 1)	

	return actor
}

func GetActorsFollowFromName(actor Actor, name string) []Actor {
	var followingActors []Actor
	follow := GetActorCollection(actor.Following)

	re := regexp.MustCompile("\\w+?$")

	for _, e := range follow.Items {
		if re.FindString(e.Id) == name {
			actor := GetActor(e.Id)
			followingActors = append(followingActors, actor)
		}
	}

	return followingActors
}

func GetActorsFollowPostFromId(actors []Actor, id string) Collection{
	var collection Collection

	for _, e := range actors {
		tempCol := GetActorCollection(e.Id + "/" + id)
		if len(tempCol.OrderedItems) > 0 {
			collection = tempCol
		}
	}

	return collection
}

func GetActorFromPath(location string, prefix string) string {
	pattern := fmt.Sprintf("%s([^/\n]+)(/.+)?", prefix)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(location)

	var actor string

	if(len(match) < 1 ) {
		actor = "/"
	} else {
		actor = strings.Replace(match[1], "/", "", -1)
	}

	if actor == "/" || actor == "outbox" || actor == "inbox" || actor == "following" || actor == "followers" {
		actor = Domain
	} else {
		actor = actor
	}
	
	return actor
}

func GetActorByName(name string) Actor {
	var actor Actor
		for _, e := range *Boards {
			boardActor := GetActor(e.Id)
			if boardActor.Name == name {
				actor = boardActor
			}
		}

	return actor
}

func WantToServe(actorName string) (Collection, bool) {

	var collection Collection
	serve := false
	
	for _, e := range *Boards {
		boardActor := GetActor(e.Id)
		if boardActor.Name == actorName {
			serve = true
			collection = GetActorCollection(boardActor.Outbox)
			collection.Actor = boardActor.Id
		}
	}

	return collection, serve
}

func CatalogGet(w http.ResponseWriter, r *http.Request, db *sql.DB){
	name := GetActorFromPath(r.URL.Path, "/")
	actor := GetActorByName(name)

	t := template.Must(template.ParseFiles("./static/main.html", "./static/ncatalog.html"))			

	returnData := new(PageData)

	var mergeCollection Collection

	actorCol := GetActorCollection(actor.Outbox)	

	for _, e := range actorCol.OrderedItems {
		mergeCollection.OrderedItems = append(mergeCollection.OrderedItems, e)
	}

	re := regexp.MustCompile("(https://|http://)?(www)?.+/")

	domainURL := re.FindString(actor.Id)

	re = regexp.MustCompile("/$")

	domainURL = re.ReplaceAllString(domainURL, "")

	d := StripTransferProtocol(domainURL)

	if d == Domain {
		followCol := GetObjectsFromFollow(actor)	
		for _, e := range followCol {

			mergeCollection.OrderedItems = append(mergeCollection.OrderedItems, e)
		}
	}


	DeleteRemovedPosts(db, &mergeCollection)
	mergeCollection.OrderedItems = DeleteTombstonePosts(&mergeCollection)
	
	sort.Sort(ObjectBaseSortDesc(mergeCollection.OrderedItems))

	returnData.Board.Name = actor.Name
	returnData.Board.PrefName = actor.PreferredUsername
	returnData.Board.InReplyTo = ""
	returnData.Board.To = actor.Outbox
	returnData.Board.Actor = actor.Id
	returnData.Key = *Key
	
	id, _ := GetPasswordFromSession(r)


	if StripTransferProtocol(actor.Id) == id || Domain == id {
		returnData.Board.IsMod = true
	} else {
		returnData.Board.IsMod = false		
	}	

	resp, err := http.Get(domainURL + "/getcaptcha")

	CheckError(err, "error getting captcha")

	body, _ := ioutil.ReadAll(resp.Body)			

	returnData.Board.Captcha = domainURL + "/" + string(body)

	re = regexp.MustCompile("\\w+\\.\\w+$")

	code := re.FindString(returnData.Board.Captcha)

	re = regexp.MustCompile("\\w+")

	code = re.FindString(code)
	
	returnData.Board.CaptchaCode = code	

	returnData.Title = "/" + actor.Name + "/ - " + actor.PreferredUsername

	returnData.Boards = GetBoardCollection()

	returnData.Posts = mergeCollection.OrderedItems

	returnData.Key = *Key

	t.ExecuteTemplate(w, "layout",  returnData)
}

func OutboxGet(w http.ResponseWriter, r *http.Request, db *sql.DB, collection Collection){

	t := template.Must(template.ParseFiles("./static/main.html", "./static/nposts.html"))	

	id, _ := GetPasswordFromSession(r)														

	actor := GetActor(collection.Actor)	
	
	postNum := strings.Replace(r.URL.EscapedPath(), "/" + actor.Name + "/", "", 1)

	page, _ := strconv.Atoi(postNum)
	
	returnData := new(PageData)

	returnData.Board.Name = actor.Name
	returnData.Board.PrefName = actor.PreferredUsername
	returnData.Board.Summary = actor.Summary
	returnData.Board.InReplyTo = ""
	returnData.Board.To = actor.Outbox
	returnData.Board.Actor = actor.Id		
	returnData.CurrentPage = page

	if StripTransferProtocol(actor.Id) == id || Domain == id {
		returnData.Board.IsMod = true
	} else {
		returnData.Board.IsMod = false		
	}

	re := regexp.MustCompile("(https://|http://)?(www)?.+/")

	domainURL := re.FindString(actor.Id)

	re = regexp.MustCompile("/$")

	domainURL = re.ReplaceAllString(domainURL, "")

	resp, err := http.Get(domainURL + "/getcaptcha")

	CheckError(err, "error getting captcha")

	body, _ := ioutil.ReadAll(resp.Body)			

	returnData.Board.Captcha = domainURL + "/" + string(body)

	re = regexp.MustCompile("\\w+\\.\\w+$")

	code := re.FindString(returnData.Board.Captcha)

	re = regexp.MustCompile("\\w+")

	code = re.FindString(code)
	
	returnData.Board.CaptchaCode = code

	returnData.Title = "/" + actor.Name + "/ - " + actor.PreferredUsername

	returnData.Key = *Key	

	var boardCollection []Board

	var mergeCollection Collection

	for _, e := range collection.OrderedItems {
		mergeCollection.OrderedItems = append(mergeCollection.OrderedItems, e)
	}

	if StripTransferProtocol(domainURL) == Domain {
		followCol := GetObjectsFromFollow(actor)	
		for _, e := range followCol {
			mergeCollection.OrderedItems = append(mergeCollection.OrderedItems, e)			
		}
	}

	DeleteRemovedPosts(db, &mergeCollection)
	mergeCollection.OrderedItems = DeleteTombstonePosts(&mergeCollection)

	sort.Sort(ObjectBaseSortDesc(mergeCollection.OrderedItems))

	for _, e := range mergeCollection.OrderedItems {
		sort.Sort(ObjectBaseSortAsc(e.Replies.OrderedItems))
	}

	for _, e := range *Boards {
		board := new(Board)		
		boardActor := GetActor(e.Id)
		board.Name = "/" + boardActor.Name + "/"
		board.PrefName = boardActor.PreferredUsername
		board.Location = "/" + boardActor.Name
		boardCollection = append(boardCollection, *board)
	}	

	returnData.Boards = boardCollection


	offset := 8
	start := page * offset
	for i := 0; i < offset; i++ {
		length := len(mergeCollection.OrderedItems)
		current := start + i
		if(current < length) {
			returnData.Posts = append(returnData.Posts, mergeCollection.OrderedItems[current])
		}
	}


	for i, e := range returnData.Posts {
		var replies []ObjectBase
		for i := 0; i < 5; i++ {
			cur := len(e.Replies.OrderedItems) - i - 1
			if cur > -1 {
				replies = append(replies, e.Replies.OrderedItems[cur])
			}
		}

		var orderedReplies []ObjectBase
		for i := 0; i < 5; i++ {
			cur := len(replies) - i - 1
			if cur > -1 {
				orderedReplies = append(orderedReplies, replies[cur])
			}
		}
		returnData.Posts[i].Replies.OrderedItems = orderedReplies
	}

	var pages []int
	pageLimit := math.Round(float64(len(mergeCollection.OrderedItems) / offset))
	for i := 0.0; i <= pageLimit; i++ {
		pages = append(pages, int(i))
	}

	returnData.Pages = pages
	returnData.TotalPage = len(returnData.Pages) - 1

	w.Header().Set("Host", LocalDomain)
	t.ExecuteTemplate(w, "layout",  returnData)		
}

func PostGet(w http.ResponseWriter, r *http.Request, db *sql.DB){

	t := template.Must(template.ParseFiles("./static/main.html", "./static/npost.html"))
	
	id, _ := GetPasswordFromSession(r)															

	type SinglePageData struct {
		Title string
		Board Board
		Boards []Board
		Posts ObjectBase
		Key string
		IsMod bool
	}

	path := r.URL.Path
	name := GetActorFromPath(path, "/")
	re := regexp.MustCompile("\\w+$")
	postId := re.FindString(path)
	actor := GetActorByName(name)


	inReplyTo := actor.Id + "/" + postId

	returnData := new(SinglePageData)

	returnData.Board.Name = actor.Name
	returnData.Board.PrefName = actor.PreferredUsername
	returnData.Board.To = actor.Outbox
	returnData.Board.Actor = actor.Id
	returnData.Board.Summary = actor.Summary

	if StripTransferProtocol(actor.Id) == id  || Domain == id {
		returnData.Board.IsMod = true
	} else {
		returnData.Board.IsMod = false		
	}	

	re = regexp.MustCompile("(https://|http://)?(www)?.+/")

	domainURL := re.FindString(actor.Id)

	re = regexp.MustCompile("/$")

	domainURL = re.ReplaceAllString(domainURL, "")

	resp, err := http.Get(domainURL + "/getcaptcha")

	CheckError(err, "error getting captcha")

	body, _ := ioutil.ReadAll(resp.Body)			

	returnData.Board.Captcha = domainURL + "/" + string(body)

	re = regexp.MustCompile("\\w+\\.\\w+$")

	code := re.FindString(returnData.Board.Captcha)

	re = regexp.MustCompile("\\w+")

	code = re.FindString(code)
	
	returnData.Board.CaptchaCode = code	

	returnData.Title = "/" + returnData.Board.Name + "/ - " + returnData.Board.PrefName

	returnData.Key = *Key	

	var boardCollection []Board

	boardCollection = GetBoardCollection()

	returnData.Boards = boardCollection

	re = regexp.MustCompile("f\\w+-\\w+")

	if re.MatchString(path) {
		name := GetActorFollowNameFromPath(path)
		followActors := GetActorsFollowFromName(actor, name)
		followCollection := GetActorsFollowPostFromId(followActors, postId)
		
		DeleteRemovedPosts(db, &followCollection)
		followCollection.OrderedItems = DeleteTombstonePosts(&followCollection)
		
		returnData.Board.InReplyTo = followCollection.OrderedItems[0].Id
		returnData.Posts = followCollection.OrderedItems[0]

		sort.Sort(ObjectBaseSortAsc(returnData.Posts.Replies.OrderedItems))				
	} else {
		returnData.Board.InReplyTo = inReplyTo

		collection := GetActorCollection(inReplyTo)
		
		DeleteRemovedPosts(db, &collection)
		collection.OrderedItems = DeleteTombstonePosts(&collection)
		
		returnData.Posts = collection.OrderedItems[0]
		sort.Sort(ObjectBaseSortAsc(returnData.Posts.Replies.OrderedItems))						
	}

	t.ExecuteTemplate(w, "layout",  returnData)			
}

func GetBoardCollection() []Board {
	var collection []Board
	for _, e := range *Boards {
		var board Board
		boardActor := GetActor(e.Id)
		board.Name = "/" + boardActor.Name + "/"
		board.PrefName = boardActor.PreferredUsername
		board.Location = "/" + boardActor.Name
		collection = append(collection, board)
	}

	return collection
}

func GetObjectsFromFollow(actor Actor) []ObjectBase {
	var followingCol Collection
	var followObj []ObjectBase
	followingCol = GetActorCollection(actor.Following)
	for _, e := range followingCol.Items {
		var followOutbox Collection
		var actor Actor
		actor = GetActor(e.Id)
		followOutbox = GetActorCollection(actor.Outbox)
		for _, e := range followOutbox.OrderedItems {
			followObj = append(followObj, e)
		}
	}
	return followObj
}

func ParseCommentForReply(comment string) string {
	
	re := regexp.MustCompile("(>>)(https://|http://)?(www\\.)?.+\\/\\w+")	
	match := re.FindAllStringSubmatch(comment, -1)

	var links []string

	for i:= 0; i < len(match); i++ {
		str := strings.Replace(match[i][0], ">>", "", 1)
		str = strings.Replace(str, "http://", "", 1)
		str = strings.Replace(str, "https://", "", 1)		
		//		str = "https://" + str
		links = append(links, str)
	}

	if(len(links) > 0){
		_, isValid := CheckValidActivity(links[0])

		if(isValid) {
			return links[0]
		}
	}
	
	return ""
}

func CheckValidActivity(id string) (Collection, bool) {

	req, err := http.NewRequest("GET", TP + "" + id, nil)

	if err != nil {
		fmt.Println("error with request")
		panic(err)
	}

	req.Header.Set("Accept", "json/application/activity+json")

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		fmt.Println("error with response")
		panic(err)		
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var respCollection Collection

	err = json.Unmarshal(body, &respCollection)

	if err != nil {
		panic(err)
	}

	if respCollection.AtContext.Context == "https://www.w3.org/ns/activitystreams" &&  respCollection.OrderedItems[0].Id != "" {
		return respCollection, true;
	}

	return respCollection, false;
}

func ParseOptions(r *http.Request, obj ObjectBase) ObjectBase {
	options := r.FormValue("options")
	if options != "" {
		option := strings.Split(options, ";")
		email := regexp.MustCompile(".+@.+\\..+")		
		wallet := regexp.MustCompile("wallet:.+")
		delete := regexp.MustCompile("delete:.+")
		for _, e := range option {
			if e == "noko" {
				obj.Option = append(obj.Option, "noko")				 
			} else if e == "sage" {
				obj.Option = append(obj.Option, "sage")				 				
			} else if e == "nokosage" {
				obj.Option = append(obj.Option, "nokosage")				 								
			} else if email.MatchString(e) {
				obj.Option = append(obj.Option, "email:" + e)				 												
			} else if wallet.MatchString(e) {
				obj.Option = append(obj.Option, "wallet")				 																
				var wallet CryptoCur
				value := strings.Split(e, ":")
				wallet.Type = value[0]
				wallet.Address = value[1]
				obj.Wallet = append(obj.Wallet, wallet)
			} else if delete.MatchString(e) {
				obj.Option = append(obj.Option, e)
			}
		}
	}

	return obj
}

func DeleteTombstonePosts(collection *Collection) []ObjectBase {
	var nColl Collection
	
	for _, e := range collection.OrderedItems {
		if e.Type != "Tombstone" {
			nColl.OrderedItems = append(nColl.OrderedItems, e)
		}
	}
	return nColl.OrderedItems
}

func DeleteRemovedPosts(db *sql.DB, collection *Collection) {

	removed := GetLocalDeleteDB(db)

	for p, e := range collection.OrderedItems {
		for _, j := range removed {
			if e.Id == j.ID {
				if j.Type == "attachment" {
					collection.OrderedItems[p].Attachment[0].Href = "/public/removed.png"
					collection.OrderedItems[p].Attachment[0].Name = "deleted"					
					collection.OrderedItems[p].Attachment[0].MediaType = "image/png"					
				} else {
					collection.OrderedItems[p].AttributedTo = "deleted"
					collection.OrderedItems[p].Content = ""
					collection.OrderedItems[p].Type = "Tombstone"
					if collection.OrderedItems[p].Attachment != nil {					
						collection.OrderedItems[p].Attachment[0].Href = "/public/removed.png"
						collection.OrderedItems[p].Attachment[0].Name = "deleted"
						collection.OrderedItems[p].Attachment[0].MediaType = "image/png"
					}
				}
			}
		}
		for i, r := range e.Replies.OrderedItems {
			for _, k := range removed {
				if r.Id == k.ID {
					if k.Type == "attachment" {
						e.Replies.OrderedItems[i].Attachment[0].Href = "/public/removed.png"
						e.Replies.OrderedItems[i].Attachment[0].Name = "deleted"
						e.Replies.OrderedItems[i].Attachment[0].MediaType = "image/png"
					} else {
						e.Replies.OrderedItems[i].AttributedTo = "deleted"
						e.Replies.OrderedItems[i].Content = ""
						e.Replies.OrderedItems[i].Type = "Tombstone"
						if e.Replies.OrderedItems[i].Attachment != nil {
							e.Replies.OrderedItems[i].Attachment[0].Name = "deleted"												
							e.Replies.OrderedItems[i].Attachment[0].Href = "/public/removed.png"						
							e.Replies.OrderedItems[i].Attachment[0].MediaType = "image/png"
						}
					}
				}
			}
		}
	}
}

func neuter(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if strings.HasSuffix(r.URL.Path, "/") {
            http.NotFound(w, r)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func GetPasswordFromSession(r *http.Request) (string, string) {

	c, err := r.Cookie("session_token")

	if err != nil {
		return "", ""
	}

	sessionToken := c.Value

	response, err := cache.Do("GET", sessionToken)

	if CheckError(err, "could not get session from cache") != nil {
		return "", ""
	}

	token := fmt.Sprintf("%s", response)

	parts := strings.Split(token, "|")

	return parts[0], parts[1]
}

func GetClientKey() string{
	file, err := os.Open("clientkey")

	CheckError(err, "could not open client key in file")

	defer file.Close()

	scanner := bufio.NewScanner(file)
	var line string
	for scanner.Scan() {
		line = fmt.Sprintf("%s", scanner.Text())
	}

	return line
}

func CreateClientKey(){

	file, err := os.Create("clientkey")

	CheckError(err, "could not create client key in file")

	defer file.Close()

	file.WriteString(CreateKey(32))	
}

func CreateKey(len int) string {
	var key string
	str := (CreateTripCode(RandomID(len)))
	for i := 0; i < len; i++ {
		key += fmt.Sprintf("%c", str[i])			
	}
	return key
}

func CreateTripCode(input string) string {
	cmd := exec.Command("sha512sum")
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()

	CheckError(err, "error with create trip code")

	return out.String()
}

func RandomID(size int) string {
	rand.Seed(time.Now().UnixNano())
	domain := "0123456789ABCDEF"
	rng := size
	newID := ""
	for i := 0; i < rng; i++ {
		newID += string(domain[rand.Intn(len(domain))])
	}
	
	return newID
}

func GetConfigValue(value string) string{
	file, err := os.Open("config")

	CheckError(err, "there was an error opening the config file")

	defer file.Close()

	lines := bufio.NewScanner(file)

	for lines.Scan() {
		line := strings.SplitN(lines.Text(), ":", 2)
		if line[0] == value {
			return line[1]
		}
	}

	return ""
}

func StripTransferProtocol(value string) string {
	re := regexp.MustCompile("(http://|https://)?(www.)?")

	value = re.ReplaceAllString(value, "")

	return value
}

func GetInstanceTP(instance  string) string {
	actor := GetActor(Domain)

	re := regexp.MustCompile("(https://|http://)")

	return re.FindString(actor.Id)
}


type ObjectBaseSortDesc []ObjectBase
func (a ObjectBaseSortDesc) Len() int { return len(a) }
func (a ObjectBaseSortDesc) Less(i, j int) bool { return a[i].Updated > a[j].Updated }
func (a ObjectBaseSortDesc) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

type ObjectBaseSortAsc []ObjectBase
func (a ObjectBaseSortAsc) Len() int { return len(a) }
func (a ObjectBaseSortAsc) Less(i, j int) bool { return a[i].Published < a[j].Published }
func (a ObjectBaseSortAsc) Swap(i, j int) { a[i], a[j] = a[j], a[i] }


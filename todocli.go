package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Email    string
	Name     string
	Password string
}

type Task struct {
	ID         int
	Title      string
	CategoryID int
	Duedate    string
	UserID     int
	IsDone     bool
}

type Category struct {
	ID     int
	Title  string
	Color  string
	UserID int
}

var (
	userStorage       []User
	userAccount       *User
	taskStorage       []Task
	categoryStorage   []Category
	serializationMode string
)

const (
	MadeUpSerializationMode = "madeup"
	JsonSerializationMode   = "json"
)

func main() {
	fmt.Println("Hello to TODO app")
	serializeMode := flag.String("serialize_mode", "json", "serialization mode")
	command := flag.String("command", "no value", "command to run")

	var store userReadStore
	var userFileStore fileStore
	store = userFileStore
	store.Load(*serializeMode)
	//loadUserStorageFromFile(*serializeMode)

	flag.Parse()
	switch *serializeMode {
	case MadeUpSerializationMode:
		serializationMode = MadeUpSerializationMode
	default:
		serializationMode = JsonSerializationMode
	}
	for {
		runCommand(*command)
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("another command please: ")
		fmt.Println("1-creat-task")
		fmt.Println("2-creat-category")
		fmt.Println("3-register-user")
		fmt.Println("4-list-task")
		fmt.Println("5-login")
		fmt.Println("5-exit")
		scanner.Scan()
		*command = scanner.Text()
		fmt.Println(userStorage)
	}
}

func runCommand(command string) {
	scanner := bufio.NewScanner(os.Stdin)
	if userAccount != nil {
		//userAccount.print()
	} else {
		fmt.Println("you are not logged in")
	}
	if command != "register-user" && command != "exit" && userAccount == nil {
		login(scanner)
	}

	var store userWriteStore
	var userFileStore = fileStore{
		filePath: "user.txt",
	}
	store = userFileStore
	switch command {
	case "creat-task":
		createTask(scanner)
	case "creat-category":
		createCategory(scanner)
	case "register-user":
		registerUser(scanner, store)
	case "list-task":
		listTasks()
	case "login":
		login(scanner)
	case "exit":
		os.Exit(0)
	default:
		fmt.Println("command is not valid", command)
	}
}

func createTask(scanner *bufio.Scanner) (string, string, string) {
	fmt.Println("**CREATING TASK**")
	fmt.Println("categories: ", categoryStorage)
	var title, duedate, category string
	fmt.Println("please enter the task title")
	scanner.Scan()
	title = scanner.Text()

	fmt.Println("please enter the task category id")
	scanner.Scan()
	category = scanner.Text()
	categoryID, err := strconv.Atoi(category)
	if err != nil {
		fmt.Printf("category id is not valid integer , %v\n", err)
	}
	relativeCategoryFound := false
	for _, categoryItem := range categoryStorage {
		if categoryItem.UserID == userAccount.ID && categoryID == categoryItem.ID {
			relativeCategoryFound = true
		}
	}
	if !relativeCategoryFound {
		fmt.Println("category did not found !")
		return "false", "false", "false"
	}
	fmt.Println("please enter the task due date")
	scanner.Scan()
	duedate = scanner.Text()
	task := Task{
		ID:         rand.Int(),
		Title:      title,
		CategoryID: categoryID,
		Duedate:    duedate,
		UserID:     userAccount.ID,
		IsDone:     false,
	}
	taskStorage = append(taskStorage, task)
	return title, duedate, category
}
func createCategory(scanner *bufio.Scanner) (string, string) {
	var title, color string
	fmt.Println("**CREATING CATEGORY**")
	fmt.Println("please enter the category title")
	scanner.Scan()
	title = scanner.Text()

	fmt.Println("please enter the category color")
	scanner.Scan()
	color = scanner.Text()
	category := Category{
		ID:     rand.Int(),
		Title:  title,
		Color:  color,
		UserID: userAccount.ID,
	}
	categoryStorage = append(categoryStorage, category)
	return title, color
}

type userWriteStore interface {
	Save(u User)
}

type userReadStore interface {
	Load(serializationMode string) []User
}

func registerUser(scanner *bufio.Scanner, store userWriteStore) (int, string, string, string) {
	var email, password, name string
	var id int
	fmt.Println("**CREATING USER**")
	fmt.Println("please enter the user email")
	scanner.Scan()
	email = scanner.Text()

	fmt.Println("please enter the user name")
	scanner.Scan()
	name = scanner.Text()

	fmt.Println("please enter the user password")
	scanner.Scan()
	password = scanner.Text()
	id = rand.Int()
	password = hashThePassword(password)
	user := User{
		ID:       id,
		Email:    email,
		Name:     name,
		Password: password,
	}
	userStorage = append(userStorage, user)
	//writeUserToFile(user)
	store.Save(user)
	return id, email, password, name
}
func login(scanner *bufio.Scanner) bool {
	fmt.Println("**LOGIN**")
	var email, password string
	fmt.Println("please enter your email")
	scanner.Scan()
	email = scanner.Text()
	doesEmailExist := false
	doesPasswordExist := false
	for _, user := range userStorage {
		if user.Email == email {
			doesEmailExist = true
		}
	}
	if !doesEmailExist {
		fmt.Println("email did not found")
		return false
	}
	fmt.Println("please enter your password")
	scanner.Scan()
	password = scanner.Text()
	for _, user := range userStorage {
		if compareThePassword(user.Password, password) {
			doesPasswordExist = true
			userAccount = &user

			break
		}
	}
	if doesEmailExist && doesPasswordExist {
		fmt.Println("you logged in successfully")
		return true
	} else {
		fmt.Println("username or password is wrong")
	}

	return false
}
func (u User) print() {
	fmt.Println("User: ", u.ID, u.Name, u.Password)
}
func listTasks() {
	fmt.Println("**LISTING TASKS**")
	for _, task := range taskStorage {
		if task.UserID == userAccount.ID {
			fmt.Println(task)
		}
	}
}

func loadUserFromStorage(store userReadStore) {
	users := store.Load()

	userStorage = append(userStorage, users...)
}

func writeUserToFile(user User) {
	var file *os.File
	_, errStat := os.Stat("user.txt")
	if errStat != nil {
		var cErr error
		file, cErr = os.Create("user.txt")

		if cErr != nil {
			fmt.Println("something wrong with creation of user.txt")
		}
	} else {
		var oErr error
		file, oErr = os.OpenFile("user.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

		if oErr != nil {
			fmt.Println("something wrong with opening of user.txt")
		}
	}
	var data []byte
	if serializationMode == "madeup" {
		data = []byte(fmt.Sprintf("id: %d, name: %s, email: %s, password: %s\n",
			user.ID, user.Name, user.Email, user.Password))
	} else if serializationMode == "json" {
		//json
		var jErr error
		data, jErr = json.Marshal(user)
		if jErr != nil {
			fmt.Println("cant marshal user struct to json", jErr)
			return
		}
		data = append(data, []byte("\n")...)
	} else {
		fmt.Println("invalid serialization mode")
		return
	}

	_, wErr := file.Write(data)

	if wErr != nil {
		fmt.Printf("cant write to the file %v\n", wErr)
	}
}

func deserializeFromData(userStr string) (User, error) {
	if userStr == " " {
		return User{}, fmt.Errorf("it is not valid")
	}
	fmt.Println(userStr)
	var userFields = strings.Split(userStr, ",")
	var user = User{}
	for _, field := range userFields {
		values := strings.Split(field, ": ")
		fieldName := strings.ReplaceAll(values[0], " ", "")
		fieldValue := values[1]
		switch fieldName {
		case "id":
			id, err := strconv.Atoi(fieldValue)
			if err != nil {
				fmt.Println("strconv error", err)

				return User{}, fmt.Errorf("")
			}
			user.ID = id
		case "name":
			user.Name = fieldValue
		case "email":
			user.Email = fieldValue
		case "password":
			user.Password = fieldValue
		}
	}
	return user, nil
}

func hashThePassword(password string) string {
	// Hashing the password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hash))
	return string(hash)
}

func compareThePassword(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false
	}
	return true
}

type fileStore struct {
	filePath string
}

func (f fileStore) Save(u User) {
	writeUserToFile(u)
}

func (f fileStore) Load(serializationMode string) []User {
	file, err := os.Open("user.txt")
	if err != nil {
		fmt.Println("cant open the file", err)
	}

	var data = make([]byte, 1024)
	_, oErr := file.Read(data)
	if oErr != nil {
		fmt.Println("cant read from the file", oErr)
	}
	var dataReadable = string(data)
	slicedUserData := strings.Split(dataReadable, "\n")
	for _, u := range slicedUserData {
		switch serializationMode {
		case "madeup":
			user, err := deserializeFromData(u)
			if err != nil {
				fmt.Println("something wrong with deserializationFromData", err)
				return nil
			}
			userStorage = append(userStorage, user)
		case "json":
			var userStruct = User{}
			uErr := json.Unmarshal([]byte(u), &userStruct)
			if err != nil {
				fmt.Println("something wrong with deserializationFromData", uErr)
				return nil
			}
			userStorage = append(userStorage, userStruct)
			fmt.Printf("user: %+v\n", userStruct)
		}
	}
	return userStorage
}

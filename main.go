package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"encoding/json"
	

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var err error
var db *sql.DB // Variable globale pour la connexion à la base de données

// Modèle de page
type Message struct {
	ID           int
	Username     string
	Title        string
	Content      string
	CreationDate string
}

// Modèle de page
type PageData struct {
	Messages []Message
}

func initDB() {
	var err error
	// Utilisation d'une variable de configuration pour les informations de connexion
	db, err = sql.Open("mysql", "root:!Art894Phil06@tcp(127.0.0.1:3306)/test")
	if err != nil {
		panic(err.Error())
	}

	// Vérifier la connexion à la base de données
	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	// Ajouter des messages de débogage
	fmt.Println("Connexion à la base de données réussie.")
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Récupérer les données du formulaire d'inscription
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Vérifier si l'utilisateur existe déjà
	if userExists(username) {
		http.Error(w, "L'utilisateur existe déjà", http.StatusBadRequest)
		return
	}

	// Créer l'utilisateur dans la base de données
	err := createUser(username, password)
	if err != nil {
		http.Error(w, "Erreur lors de l'inscription", http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page d'accueil après une inscription réussie
	http.Redirect(w, r, "/register", http.StatusSeeOther)
}

// Ajouter une fonction pour vérifier si l'utilisateur existe déjà
func userExists(username string) bool {
	query := "SELECT COUNT(*) FROM utilisateurs WHERE nom_utilisateur = ?"
	var count int
	err := db.QueryRow(query, username).Scan(&count)
	if err != nil {
		fmt.Printf("Erreur lors de la vérification de l'existence de l'utilisateur : %s\n", err)
		return false
	}
	return count > 0
}

func createUser(username, password string) error {
	// Hachage du mot de passe (assurez-vous d'utiliser une bibliothèque de hachage sécurisée)
	hashedPassword, err := hashPassword(password)
	if err != nil {
		// Imprimer l'erreur pour le débogage
		fmt.Printf("Erreur lors du hachage du mot de passe : %s\n", err)
		return err
	}
	fmt.Printf("Mot de passe haché : %s\n", hashedPassword)

	// Préparer la requête SQL pour insérer l'utilisateur dans la table Utilisateurs
	query := "INSERT INTO utilisateurs (nom_utilisateur, mot_de_passe) VALUES (?, ?)"

	// Exécuter la requête SQL avec les données fournies
	result, err := db.Exec(query, username, hashedPassword)
	if err != nil {
		// Imprimer l'erreur pour le débogage
		fmt.Printf("Erreur lors de l'insertion de l'utilisateur : %s\n", err)
		// Gérer l'erreur en retournant une erreur
		return err
	}

	// Vérifier le nombre de lignes affectées (doit être 1)
	rowsAffected, _ := result.RowsAffected()
	fmt.Printf("%d ligne(s) affectée(s) lors de l'insertion de l'utilisateur\n", rowsAffected)

	// Aucune erreur, retourner nil
	fmt.Println("Utilisateur inscrit avec succès.")
	return nil
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles("templates/register.html")
		if err != nil {
			http.Error(w, fmt.Sprintf("Erreur de parsing du fichier HTML : %s", err), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	} else if r.Method == http.MethodPost {
		createUserHandler(w, r)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func registerSubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	fmt.Printf("Données du formulaire : Username: %s, Password: %s\n", username, password)

	err := createUser(username, password)
	if err != nil {
		http.Error(w, "Erreur lors de l'inscription", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/forhum", http.StatusSeeOther)
}

func authenticateUser(w http.ResponseWriter, r *http.Request, username, password string) bool {
	// Effectuer la vérification dans la base de données
	query := "SELECT mot_de_passe FROM utilisateurs WHERE nom_utilisateur = ?"
	var hashedPassword string
	err := db.QueryRow(query, username).Scan(&hashedPassword)
	if err != nil {
		fmt.Printf("Erreur lors de la vérification de l'utilisateur : %s\n", err)
		http.Error(w, "Erreur lors de l'authentification", http.StatusInternalServerError)
		return false
	}

	// Comparer le mot de passe haché avec celui fourni
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Printf("Erreur lors de la comparaison des mots de passe : %s\n", err)
		http.Error(w, "Identifiants invalides", http.StatusUnauthorized)
		return false
	}

	// Si l'authentification réussit, définissez le cookie
	cookie := http.Cookie{
		Name:     "username",
		Value:    username,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	return true
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if r.FormValue("action") == "register" {
			err := createUser(username, password)
			if err != nil {
				http.Error(w, "Erreur lors de l'inscription", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/forhum", http.StatusSeeOther)
			return
		} else {
			if authenticateUser(w, r, username, password) {
				http.Redirect(w, r, "/forhum", http.StatusSeeOther)
				return
			}

			// Rediriger vers /register en cas d'échec de connexion
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}
	}

	// Si la méthode n'est pas POST, afficher le formulaire de connexion
	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur de parsing du fichier HTML : %s", err), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func saveMessage(username, title, content string) error {
	// Préparer la requête SQL pour insérer le message dans la table Messages
	query := "INSERT INTO messages (nom_utilisateur, titre, contenu, date_creation) VALUES (?, ?, ?, NOW())"
	fmt.Println("Query:", query) // Imprimez la requête SQL pour le débogage

	// Exécuter la requête SQL avec les données fournies
	_, err := db.Exec(query, username, title, content)
	if err != nil {
		return err
	}

	return nil
}

func getMessages() ([]Message, error) {
    query := `SELECT m.id, u.nom_utilisateur, m.titre, m.contenu, m.date_creation 
               FROM messages m 
               JOIN utilisateurs u ON m.nom_utilisateur = u.nom_utilisateur 
               LEFT JOIN supprimer s ON m.id = s.message_id 
               WHERE s.message_id IS NULL 
               ORDER BY m.date_creation DESC`
    rows, err := db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var messages []Message
    for rows.Next() {
        var msg Message
        err := rows.Scan(&msg.ID, &msg.Username, &msg.Title, &msg.Content, &msg.CreationDate)
        if err != nil {
            return nil, err
        }
        messages = append(messages, msg)
    }

    return messages, nil
}


func discussionHandler(w http.ResponseWriter, r *http.Request) {
	// Charger et afficher le fichier HTML homepage.html
	tmpl, err := template.ParseFiles("templates/homepage.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur de parsing du fichier HTML : %s", err), http.StatusInternalServerError)
		return
	}

	// Récupérer le nom d'utilisateur depuis les cookies
	usernameCookie, err := r.Cookie("username")
	if err != nil {
		http.Error(w, "Erreur de récupération du nom d'utilisateur", http.StatusUnauthorized)
		return
	}
	username := usernameCookie.Value

	// Récupérer les messages depuis la base de données
	messages, err := getMessages()
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des messages", http.StatusInternalServerError)
		return
	}

	// Créer une structure de données pour stocker les messages et le nom d'utilisateur
	data := struct {
		Messages []Message
		Username string
	}{
		Messages: messages,
		Username: username,
	}

	// Exécuter le modèle avec les données et écrire la réponse
	err = tmpl.Execute(w, data)
	if err != nil {
		return
	}
}

func saveMessageHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer le nom d'utilisateur depuis les cookies
	usernameCookie, err := r.Cookie("username")
	if err != nil {
		http.Error(w, "Erreur de récupération du nom d'utilisateur depuis les cookies", http.StatusUnauthorized)
		return
	}
	username := usernameCookie.Value

	title := r.FormValue("title")
	content := r.FormValue("content")

	err = saveMessage(username, title, content)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors de l'enregistrement du message : %s", err), http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page d'accueil après l'enregistrement du message
	http.Redirect(w, r, "/homepage", http.StatusSeeOther)
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	// Charger et afficher le fichier HTML createpost.html
	tmpl, err := template.ParseFiles("templates/createpost.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur de parsing du fichier HTML : %s", err), http.StatusInternalServerError)
		return
	}

	// Récupérer les catégories depuis la base de données
	categories, err := getCategories()
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des catégories", http.StatusInternalServerError)
		return
	}

	// Créer une structure de données pour stocker les catégories
	data := struct {
		Categories []string
	}{
		Categories: categories,
	}

	// Exécuter le modèle avec les données et écrire la réponse
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors de l'exécution du modèle : %s", err), http.StatusInternalServerError)
		return
	}
}

func getUserIDByUsername(username string) (int, error) {
	var userID int
	query := "SELECT id FROM utilisateurs WHERE nom_utilisateur = ?"
	err := db.QueryRow(query, username).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func getFavoriteMessages(userID int) ([]Message, error) {
	query := "SELECT m.id, u.nom_utilisateur, m.titre, m.contenu, m.date_creation FROM messages m JOIN utilisateurs u ON m.nom_utilisateur = u.nom_utilisateur JOIN likes l ON m.id = l.MessageID WHERE l.UserID = ? ORDER BY m.date_creation DESC"
	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var favoriteMessages []Message
	for rows.Next() {
		var msg Message
		err := rows.Scan(&msg.ID, &msg.Username, &msg.Title, &msg.Content, &msg.CreationDate)
		if err != nil {
			return nil, err
		}
		favoriteMessages = append(favoriteMessages, msg)
	}

	return favoriteMessages, nil
}

func likeMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Récupérer l'ID de l'utilisateur depuis les cookies
	usernameCookie, err := r.Cookie("username")
	if err != nil {
		http.Error(w, "Erreur de récupération du nom d'utilisateur depuis les cookies", http.StatusUnauthorized)
		return
	}
	username := usernameCookie.Value

	// Récupérer l'ID de l'utilisateur
	userID, err := getUserIDByUsername(username)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération de l'ID de l'utilisateur", http.StatusInternalServerError)
		return
	}

	// Récupérer l'ID du message à partir de la requête POST
	messageID := r.FormValue("messageID")
	// Convertir l'ID du message en entier
	messageIDInt, err := strconv.Atoi(messageID)
	if err != nil {
		http.Error(w, "ID de message non valide", http.StatusBadRequest)
		return
	}

	// Insérer une nouvelle ligne dans la table Likes avec l'ID de l'utilisateur
	query := "INSERT INTO Likes (UserID, MessageID) VALUES (?, ?)"
	_, err = db.Exec(query, userID, messageIDInt)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout du like", http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page précédente
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

func forhumHandler(w http.ResponseWriter, r *http.Request) {
	// Charger et afficher le fichier HTML forhum.html
	tmpl, err := template.ParseFiles("templates/forhum.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur de parsing du fichier HTML : %s", err), http.StatusInternalServerError)
		return
	}

	// Vous pouvez ajouter des données au modèle si nécessaire
	data := struct {
		Title string
	}{
		Title: "Forhum Page",
	}

	// Exécuter le modèle avec les données et écrire la réponse
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors de l'exécution du modèle : %s", err), http.StatusInternalServerError)
		return
	}
}

func getCategories() ([]string, error) {
	var categories []string

	rows, err := db.Query("SELECT name FROM categories")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}

	return categories, nil
}

func deleteMessage(messageID int) error {
    query := "DELETE FROM messages WHERE id = ?"
    _, err := db.Exec(query, messageID)
    if err != nil {
        return err
    }
    return nil
}

func markMessageForDeletion(messageID int) error {
    query := "INSERT INTO supprimer (message_id) VALUES (?)"
    _, err := db.Exec(query, messageID)
    if err != nil {
        return err
    }
    return nil
}
func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
        return
    }

    // Récupérer l'ID du message à supprimer
    var messageID struct {
        MessageID int `json:"message_id"`
    }
    err := json.NewDecoder(r.Body).Decode(&messageID)
    if err != nil {
        http.Error(w, "Erreur lors de la lecture de l'ID du message", http.StatusBadRequest)
        return
    }

    err = deleteMessage(messageID.MessageID)
    if err != nil {
        http.Error(w, "Erreur lors de la suppression du message", http.StatusInternalServerError)
        return
    }

    // Envoyer une réponse JSON pour indiquer que la suppression a réussi
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status": "success",
    })
}

func main() {
	// Ouvrir la connexion à la base de données au démarrage
	initDB()
	defer db.Close()

	// Créer un gestionnaire de fichiers statiques pour servir les fichiers depuis le répertoire "assets"
	fileServer := http.FileServer(http.Dir("assets"))

	// Assurez-vous que les requêtes statiques sont gérées par le gestionnaire de fichiers statiques
	http.Handle("/assets/", http.StripPrefix("/assets/", fileServer))

	// Définir les autres gestionnaires de route HTTP

	http.HandleFunc("/createpost", createPostHandler)
	http.HandleFunc("/homepage", discussionHandler)
	http.HandleFunc("/save-message", saveMessageHandler)
	http.HandleFunc("/", registerHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", authHandler)
	http.HandleFunc("/like-message", likeMessageHandler)
	http.HandleFunc("/delete-message", deleteMessageHandler)

	http.HandleFunc("/forhum", forhumHandler) // Ajoutez cette ligne pour la nouvelle page forhum

	// Démarrer le serveur HTTP
	fmt.Println("Serveur démarré sur le port 8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err.Error())
	}
}

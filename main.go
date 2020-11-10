package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		jwtHeaderName := "x-goog-iap-jwt-assertion"

		//HTTP ヘッダからJWTを取得
		tokenString := r.Header.Get(jwtHeaderName)
		w.WriteHeader(200)

		//JWTをそのまま表示
		fmt.Fprintln(w, tokenString)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("defulting to port %s", port)
	}
	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))

}

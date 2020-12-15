package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	jwt "gopkg.in/dgrijalva/jwt-go.v3"
	jose "gopkg.in/square/go-jose.v2"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		jwtHeaderName := "x-goog-iap-jwt-assertion"
		//公開鍵のURL
		jwkUrl := "https://www.gstatic.com/iap/verify/public_key-jwk"
		// issuerのURL
		issuerUrl := "https://cloud.google.com/iap"
		//audienceの値
		audience := "/projects/1013152892072/apps/phonic-axle-282407"

		//HTTP ヘッダからJWTを取得
		tokenString := r.Header.Get(jwtHeaderName)
		//公開鍵を取得
		resp, err := http.Get(jwkUrl)
		defer resp.Body.Close()
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintln(w, err)
			return
		}

		//公開鍵読み取り
		keyBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintln(w, err)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			//署名アルゴリズムの検証
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			//JWT の情報(Claims)の取得
			claims := token.Claims.(jwt.MapClaims)
			//audience ,issuerの検証
			if claims["iss"] != issuerUrl {
				return nil, fmt.Errorf("Invalid issuer:%v", claims["iss"])
			}

			//audienceの検証
			if claims["aud"] != audience {
				return nil, fmt.Errorf("invalid auduence: %v", claims["aud"])

			}

			//公開鍵をパース
			var keySet jose.JSONWebKeySet
			err := json.Unmarshal(keyBody, &keySet)

			//複数の公開鍵からトークンの"kid"に合致する公開鍵を返却
			kid := token.Header["kid"].(string)
			return keySet.Key(kid)[0].Key, err
		})

		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintln(w, err)
			return
		}

		//サブジェクトとメールアドレスを取得
		claims := token.Claims.(jwt.MapClaims)
		email := claims["email"]
		subject := claims["sub"]

		w.WriteHeader(200)
		//サブジェクトとメールアドレスを表示する
		fmt.Fprintln(w, email)
		fmt.Fprintln(w, subject)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("defulting to port %s", port)
	}
	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))

}

func indexHandler(w http.ResponseWriter, r *http.Request) {

}

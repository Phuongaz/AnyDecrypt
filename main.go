package main

import (
	"decryptany/decrypt"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", mainpage)

	http.HandleFunc("/decrypt", decrypt.Decrypt)
	fmt.Printf("Starting server at port 8080")
	http.ListenAndServe(":8080", nil)
}

func mainpage(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("ip")
	if url == "" {
		p := "." + r.URL.Path
		if p == "./" {
			p = "./index.html"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, p)
	}
}

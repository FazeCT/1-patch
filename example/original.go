package main

import "fmt"

var GLOBAL_VAR = 1000
var GLOBAL_VAR_2 = 2000

func lmao() {
    fmt.Println("lmao")
}

func add(a int, b int) int {
	lmao();
    return a + b
}

func main() {
    fmt.Println(add(GLOBAL_VAR, GLOBAL_VAR_2))
}
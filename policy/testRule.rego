package main

deny contains msg if {
  not startswith(input.password, "![") 
  msg := "password should be encrypted"
  
}

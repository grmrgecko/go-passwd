# go-passwd

This is a libxcrypt compatible password hashing library for the Go language. The passwords generated with this library is fully compatible with libxcrypt which can be used to generate or test passwords in use by software such as MySQL or the Linux shadow system.

## Install

```
go get github.com/GRMrGecko/go-passwd
```

## Docs

[https://pkg.go.dev/github.com/GRMrGecko/go-passwd](https://pkg.go.dev/github.com/GRMrGecko/go-passwd)

## Example

```go
package main

import (
	"github.com/GRMrGecko/go-passwd"
	"log"
)

func main() {
	result, err := passwd.SCheckPassword("$y$j9T$Q3N1jZa3Cp.yNINNDt5dDgYkHU7k$9o7WJJB5F.tTEhZdz6T6LMWY/0C3JkhvmcNyUPvUBlC", "Test")
	if err != nil {
		log.Fatalln(err)
	}

	if result {
		log.Println("Password confirmed, saving new password.")

		pw := passwd.NewSHA512CryptPasswd()
		hash, err := pw.SHashPassword("New Password!!!")
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("The new password hash to save is:", hash)
	}
}

```

Example output:
```
$ ./test
2024/09/07 18:42:35 Password confirmed, saving new password.
2024/09/07 18:42:35 The new password hash to save is: $6$4Eu/l5e.otcRj0rJ$YAlwxJD9pZY9.Z2TjseCbkXiUIrFU2AXh9DPEm5Z1SagxP..xaQCsz7jAgfW4nmUbLh.o23pEZGvvxPCLltf11
```

## Known issues

 - It is possible to generate password hashes that are incompatible with libxcrypt by setting a large round count. This may be mitigated in the future by adding an option to disable compatibility and otherwise require compatible parameters to be set.
 - The bcrypt hashing algorithms are not implemented yet, it may be implemented in the near futre.

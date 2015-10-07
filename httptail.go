package main

import (
    "os"
    "io"
    "net/http"
    "crypto/tls"
    "golang.org/x/crypto/ssh/terminal"
    "fmt"
    "log"
    "flag"
    "syscall"
    "io/ioutil"
    "math/rand"
    "time"
)

func init() {
    rand.Seed(time.Now().UnixNano())
}

func main() {
    httpTail := HttpTail{
        Client: &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                },
            },
        },
    }

    flag.StringVar(&httpTail.Username, "u", "", "Specify the username on an HTTP server")
    readPassword := flag.Bool("p", false, "Specify the password on an HTTP server")

    flag.Parse()

    if *readPassword {
        pwd, err := ReadPassword()
        if err != nil {
            log.Fatal(err)
        }
        httpTail.SetPassword(string(pwd))
    }

    httpTail.Url = flag.Arg(0)
    if _, err := io.Copy(os.Stdout, &httpTail); err != nil {
        log.Fatal(err)
    }
}

type HttpTail struct {
    Url string
    Client *http.Client
    Username string
    Password string
    Pos int64
    Key []byte
}

func (self *HttpTail) SetPassword(p string) {
    // TODO: crypt with random key
    self.Password = p
}

func (self *HttpTail) GetPassword() string {
    // TODO: uncrypt with random key
    return self.Password
}

func (self *HttpTail) Read(p []byte) (n int, err error) {
    if self.Pos == 0 {
        if self.Pos, err = self.ContentLength(); err != nil {
            return 0, err
        }
        if self.Pos > 1024 {
            self.Pos -= 1024
        } else {
            self.Pos = 0
        }
    }

    req, err := http.NewRequest("GET", self.Url, nil)
    if err != nil {
        return 0, err
    }

    if len(self.Username) > 0 && len(self.Password) > 0 {
        req.SetBasicAuth(self.Username, self.GetPassword())
    }

    req.Header.Set("Range", fmt.Sprintf("bytes=%d-", self.Pos))

    res, err := self.Client.Do(req)
    if err != nil {
        return 0, err
    }

    defer res.Body.Close()

    if res.StatusCode == http.StatusPartialContent {
        n, err = res.Body.Read(p)
        if err != io.EOF {
            return 0, err
        }
        self.Pos += res.ContentLength

        return n, nil
    }

    if res.StatusCode == http.StatusRequestedRangeNotSatisfiable {
        time.Sleep(1 * time.Second)
        return 0, nil
    }

    return 0, fmt.Errorf(http.StatusText(res.StatusCode))
}

func (self *HttpTail) ContentLength() (n int64, err error) {
    req, err := http.NewRequest("HEAD", self.Url, nil)
    if err != nil {
        return 0, err
    }

    if len(self.Username) > 0 && len(self.Password) > 0 {
        req.SetBasicAuth(self.Username, self.Password)
    }

    res, err := self.Client.Do(req)
    if err != nil {
        return 0, err
    }

    defer res.Body.Close()

    if res.StatusCode == http.StatusOK {
        return res.ContentLength, nil
    }

    return 0, nil
}

func ReadPassword() ([]byte, error) {
    if terminal.IsTerminal(syscall.Stdin) {
        pwd, err := terminal.ReadPassword(syscall.Stdin)
        if err != nil {
            return nil, err
        }
        return pwd, nil
    } else {
        pwd, err := ioutil.ReadAll(os.Stdin)
        if err != nil {
            return nil, err
        }
        return pwd[:len(pwd) - 1], nil
    }
}

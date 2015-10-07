package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/tls"
    "encoding/base64"
    "flag"
    "fmt"
    "golang.org/x/crypto/ssh/terminal"
    "io"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "syscall"
    "time"
)

func main() {
    httpTail, err := NewHttpTail()
    if err != nil {
        log.Fatal(err)
    }

    flag.StringVar(&httpTail.Username, "u", "", "Specify the username on an HTTP server")
    readPassword := flag.Bool("p", false, "Specify the password on an HTTP server")

    flag.Parse()

    if *readPassword {
        password, err := ReadPassword()
        if err != nil {
            log.Fatal(err)
        }
        httpTail.SetPassword(password)
    }

    httpTail.Url = flag.Arg(0)
    if _, err := io.Copy(os.Stdout, httpTail); err != nil {
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

func NewHttpTail() (*HttpTail, error) {
    key := make([]byte, 32)
    if n, err := rand.Read(key); err != nil {
        return nil, err
    } else {
        key = key[:n]
    }

    return &HttpTail{
        Client: &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                },
            },
        },
        Key: key,
    }, nil
}

func (self *HttpTail) SetPassword(password []byte) error {
    block, err := aes.NewCipher(self.Key)
    if err != nil {
        return err
    }

    ct := make([]byte, aes.BlockSize + len(password))

    iv := ct[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ct[aes.BlockSize:], password)

    self.Password = base64.URLEncoding.EncodeToString(ct)

    return nil
}

func (self *HttpTail) GetPassword() (string, error) {
    ct, _ := base64.URLEncoding.DecodeString(self.Password)

    block, err := aes.NewCipher(self.Key)
    if err != nil {
        return "", err
    }

    iv := ct[:aes.BlockSize]
    ct = ct[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)

    stream.XORKeyStream(ct, ct)

    return fmt.Sprintf("%s", ct), nil
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
        pwd, err := self.GetPassword()
        if err != nil {
            return 0, err
        }
        req.SetBasicAuth(self.Username, pwd)
    }

    req.Header.Set("Range", fmt.Sprintf("bytes=%d-", self.Pos))

    res, err := self.Client.Do(req)
    if err != nil {
        return 0, err
    }

    defer res.Body.Close()

    if res.StatusCode == http.StatusPartialContent {
        n, err = res.Body.Read(p)

        if err != nil && err != io.EOF {
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
        pwd, err := self.GetPassword()
        if err != nil {
            return 0, err
        }
        req.SetBasicAuth(self.Username, pwd)
    }

    res, err := self.Client.Do(req)
    if err != nil {
        return 0, err
    }

    defer res.Body.Close()

    if res.StatusCode == http.StatusOK {
        return res.ContentLength, nil
    }

    return 0, fmt.Errorf(http.StatusText(res.StatusCode))
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

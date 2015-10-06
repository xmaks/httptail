package main

import (
    "os"
    "io"
    "net/http"
    "crypto/tls"
    "fmt"
    "time"
    "log"
    "flag"
)

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

    flag.StringVar(&httpTail.Username, "u", "",
                   "Specify the username on an HTTP server")
    flag.StringVar(&httpTail.Password, "p", "",
                   "Specify the password on an HTTP server.")

    flag.Parse()

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
}

func (self *HttpTail) Read(p []byte) (n int, err error) {
    if self.Pos == 0 {
        if self.Pos, err = self.ContentLength(); err != nil {
            return 0, err
        }
    }

    req, err := http.NewRequest("GET", self.Url, nil)
    if err != nil {
        return 0, err
    }

    if len(self.Username) > 0 && len(self.Password) > 0 {
        req.SetBasicAuth(self.Username, self.Password)
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

package main

import (
    "bufio"
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
    "strings"
    "sync"
    "syscall"
    "time"
)

type (
    HttpUrls struct {
        *http.Client
        Quiet bool
        Follow bool
        Bytes int64
        Debug bool
        Username string
        ReadPassword bool
        Password string
        Urls []string
        SecretKey []byte
    }

    HttpUrl struct {
        *HttpUrls
        Url string
        UrlIdx int
        CurrentBytes int64
        ReadedBytes int64
    }

    HttpUrlLine struct {
        Text string
        UrlIdx int
    }
)

func main() {
    httpUrls, err := NewHttpUrls()
    if err != nil {
        log.Fatal(err)
    }
    httpUrls.Tail()
}

func NewHttpUrls() (*HttpUrls, error) {
    name, sep := os.Args[0], "/"
    idx := strings.LastIndex(name, sep)
    if idx != -1 {
        name = name[idx + len(sep):]
    }

    httpUrls := &HttpUrls{
        Client: &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                },
            },
        },
    }

    flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
    flagSet.BoolVar(&httpUrls.Quiet, "q", false, "Suppresses printing of headers")
    flagSet.BoolVar(&httpUrls.Follow, "f", false, "Do not stop when end of file is reached")
    flagSet.Int64Var(&httpUrls.Bytes, "c", 1024, "The location is number bytes")
    flagSet.BoolVar(&httpUrls.Debug, "d", false, "Show debug info")
    flagSet.StringVar(&httpUrls.Username, "u", "", "The user name to use when connecting to the HTTP server")
    flagSet.BoolVar(&httpUrls.ReadPassword, "p", false, "Reads the password to use when connecting to the HTTP server")
    flagSet.Parse(os.Args[1:])

    if httpUrls.ReadPassword {
        key := make([]byte, 32)
        if n, err := rand.Read(key); err != nil {
            return nil, err
        } else {
            httpUrls.SecretKey = key[:n]
        }

        if terminal.IsTerminal(syscall.Stdin) {
            fmt.Print("Password:")
            pwd, err := terminal.ReadPassword(syscall.Stdin)
            if err != nil {
                return nil, err
            }
            if err = httpUrls.SetPassword(pwd); err != nil {
                return nil, err
            }
        } else {
            pwd, err := ioutil.ReadAll(os.Stdin)
            if err != nil {
                return nil, err
            }
            if err = httpUrls.SetPassword(pwd); err != nil {
                return nil, err
            }
        }
    }

    urls := make(map[string]bool)
    for _, url := range flagSet.Args() {
        if _, ok := urls[url]; !ok {
            httpUrls.Urls = append(httpUrls.Urls, url)
            urls[url] = true
        }
    }

    return httpUrls, nil
}

func (this *HttpUrls) Tail() {
    var lastUrlIdx int = -1
    for line := range this.Lines() {
        if !this.Quiet && lastUrlIdx != line.UrlIdx {
            fmt.Printf("==> %s <==\n", this.Urls[line.UrlIdx])
            lastUrlIdx = line.UrlIdx
        }
        fmt.Println(line.Text)
    }
}

func (this *HttpUrls) Lines() <-chan *HttpUrlLine {
    lines := make(chan *HttpUrlLine, len(this.Urls) * 64)

    go func() {
        var wg sync.WaitGroup

        defer close(lines)
        defer wg.Wait()

        wg.Add(len(this.Urls))
        for urlIdx, url := range this.Urls {
            go func(url string, urlIdx int) {
                defer wg.Done()
                NewHttpUrl(this, url, urlIdx).Tail(lines)
            }(url, urlIdx)
        }
    }()

    return lines
}

func (this *HttpUrls) SetPassword(password []byte) error {
    block, err := aes.NewCipher(this.SecretKey)
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

    this.Password = base64.URLEncoding.EncodeToString(ct)

    return nil
}

func (this *HttpUrls) GetPassword() (string, error) {
    ct, _ := base64.URLEncoding.DecodeString(this.Password)

    block, err := aes.NewCipher(this.SecretKey)
    if err != nil {
        return "", err
    }

    iv := ct[:aes.BlockSize]
    ct = ct[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)

    stream.XORKeyStream(ct, ct)

    return fmt.Sprintf("%s", ct), nil
}

func NewHttpUrl(httpUrls *HttpUrls, url string, urlIdx int) *HttpUrl {
    return &HttpUrl{
        HttpUrls: httpUrls,
        Url: url,
        UrlIdx: urlIdx,
        CurrentBytes: -1,
        ReadedBytes: 0,
    }
}

func (this *HttpUrl) Tail(lines chan<- *HttpUrlLine) {
    n, err := this.ContentLength()
    if err != nil {
        lines <- &HttpUrlLine{
            UrlIdx: this.UrlIdx,
            Text: err.Error(),
        }
        return
    }

    this.CurrentBytes = n
    if this.CurrentBytes >= this.HttpUrls.Bytes {
        this.CurrentBytes -= this.HttpUrls.Bytes
    } else {
        this.CurrentBytes = 0
    }

    firstLine := true
    scanner := bufio.NewScanner(this)
    for scanner.Scan() {
        if firstLine {
            firstLine = false
            continue
        }
        lines <- &HttpUrlLine{
            UrlIdx: this.UrlIdx,
            Text: scanner.Text(),
        }
    }
    if err := scanner.Err(); err != nil {
        lines <- &HttpUrlLine{
            UrlIdx: this.UrlIdx,
            Text: err.Error(),
        }
    }
}

func (this *HttpUrl) ContentLength() (int64, error) {
    req, err := this.NewHttpRequest("HEAD")
    if err != nil {
        return -1, err
    }

    res, err := this.HttpUrls.Client.Do(req)
    if err != nil {
        return -1, err
    }

    defer res.Body.Close()

    if res.StatusCode == http.StatusOK {
         return res.ContentLength, nil
    }

    return -1, fmt.Errorf(http.StatusText(res.StatusCode))
}

func (this *HttpUrl) Read(p []byte) (int, error) {
    req, err := this.NewHttpRequest("GET")
    if err != nil {
        return 0, err
    }

    req.Header.Set("Range", fmt.Sprintf("bytes=%d-", this.CurrentBytes))

    res, err := this.HttpUrls.Client.Do(req)
    if err != nil {
        return 0, err
    }

    defer res.Body.Close()

    if res.StatusCode == http.StatusPartialContent {
        n, err := res.Body.Read(p)
        if err != nil && err != io.EOF {
            return 0, err
        }
        this.CurrentBytes += int64(n)
        this.ReadedBytes += int64(n)

        if !this.HttpUrls.Follow && this.ReadedBytes >= this.HttpUrls.Bytes {
            return n, io.EOF
        }

        return n, nil
    }

    if res.StatusCode == http.StatusRequestedRangeNotSatisfiable {
        time.Sleep(100 * time.Millisecond)
        return 0, nil
    }

    return 0, fmt.Errorf(http.StatusText(res.StatusCode))
}

func (this *HttpUrl) NewHttpRequest(method string) (*http.Request, error) {
    req, err := http.NewRequest(method, this.HttpUrls.Urls[this.UrlIdx], nil)
    if err != nil {
        return nil, err
    }

    if len(this.HttpUrls.Username) > 0 && len(this.HttpUrls.Password) > 0 {
        password, err := this.HttpUrls.GetPassword()
        if err != nil {
            return nil, err
        }
        req.SetBasicAuth(this.HttpUrls.Username, password)
    }

    return req, nil
}

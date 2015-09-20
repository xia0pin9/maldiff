package main

import (
    "fmt"
    "os"
    "io"
    "log"
    "sync"
    "flag"
    "bufio"
    "bytes"
    "runtime"
    "strings"
    "crypto/md5"
    "encoding/gob"
    "encoding/json"
    "io/ioutil"
    "path/filepath"
    "archive/zip"
    "github.com/xia0pin9/axmlParser"
    "github.com/syndtr/goleveldb/leveldb"
)

type AppPath struct {
    md5, path   string
}

type MetaInfo struct {
    Certmd5, Pkgname string
    Dexsize    int64
    Dirs, Files     map[string]struct{}
}

type Result struct {
    md5       []byte
    minfo     *[]byte
    //minfo   *MetaInfo
}

var (
    Trace, Info, Warning, Error             *log.Logger
    md5apk, dbname, dexdir, logfile         string
    metamap = make(map[string]*MetaInfo)
)

func Init(errorHandle io.Writer) {
    Info = log.New(errorHandle,
        "INFO: ",
        log.Ldate|log.Ltime|log.Lshortfile)

    Error = log.New(errorHandle,
        "ERROR: ",
        log.Ldate|log.Ltime|log.Lshortfile)
}

func Usage() {
    fmt.Println("Meta info collection, get meta information of apks")
    fmt.Println("   Usage: prepare -md5apk=md5apklist -dbname=benmeta")
}

func init() {
    runtime.GOMAXPROCS(runtime.NumCPU())
    flag.StringVar(&md5apk, "md5apk", "", "file name of md5 apk mapping list")
    //flag.StringVar(&objname, "objname", "", "object name where meta info are stored")
    flag.StringVar(&dbname, "dbname", "db", "fingerprint db storage name")
    flag.StringVar(&dexdir, "dexdir", "", "dir name to store dex files")
    flag.StringVar(&logfile, "logfile", "prepare.log", "file name for logging")
}

func store(fname string, data interface{}) {
    m := new(bytes.Buffer)
    enc := gob.NewEncoder(m)

    err := enc.Encode(data)
    if err != nil { panic(err) }

    file, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
    if err != nil { panic(err)}

    _, err = file.Write(m.Bytes())
    //err = ioutil.WriteFile("dep_data", m.Bytes(), 0600) 
    if err != nil { panic(err) }
    Info.Println("save metamap to disk, current size", len(metamap))
}

func load(fname string, e interface{}) {
    n,err := ioutil.ReadFile(fname)
    if err != nil { panic(err) }

    p := bytes.NewBuffer(n)
    dec := gob.NewDecoder(p)

    err = dec.Decode(e)
    if err != nil { panic(err) }
}

func extractFile(f *zip.File, dest, md5 string) error {
    rc, err := f.Open()
    if err != nil {
        return err
    }
    defer func() {
        if err := rc.Close(); err != nil {
            panic(err)
        }
    }()

    path := filepath.Join(dest, md5+".dex")
    fout, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
    if err != nil {
        return err
    }
    defer func() {
        if err := fout.Close(); err != nil {
            panic(err)
        }
    }()

    _, err = io.Copy(fout, rc)
    if err != nil {
        return err
    }

    return nil
}

func getMd5(f *zip.File) string {
    file, err := f.Open()
    if err != nil {
        panic(err)
    }
    defer file.Close()

    hash := md5.New()
    if _, err := io.Copy(hash, file); err != nil {
        panic(err)
    }
    return fmt.Sprintf("%x", hash.Sum(nil))
}

func ParseAxml(f *zip.File, listener axmlParser.Listener) (*axmlParser.Parser, error) {
    //bs, err := ioutil.ReadFile(axmlpath)
    file, err := f.Open()
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var n int64
    if size := f.FileInfo().Size(); size < 1e9 {
        n = size
    }

    buf := bytes.NewBuffer(make([]byte, 0, n+bytes.MinRead))
    _, err = buf.ReadFrom(file)

    parser := axmlParser.New(listener)
    err = parser.Parse(buf.Bytes())
    if err != nil {
        return nil, err
    }
    return parser, nil
}

func getPkgname(f *zip.File) string {
    var pkgname string

    listener := new(axmlParser.PlainListener)
    _, _ = ParseAxml(f, listener)
    for _, v := range listener.Manifest.Attrs["manifest"] {
        if v.Name == "package" {
            pkgname = v.Value
        }
    }
    return pkgname
}

func unzipApk(md5, dexdir, apkpath string) (string, string, int64, map[string]struct{}, map[string]struct{}) {
    defer func() {
        if r := recover(); r != nil {
            Error.Println("Recover from panic:", apkpath, r)
        }
    }()
    rc, err := zip.OpenReader(apkpath)
    if err != nil {
        Error.Println("Open zip file error:", apkpath, err)
    }
    defer rc.Close()

    var certmd5, pkgname, dname, fname string
    var dexsize int64
    //var normal bool
    dirs := make(map[string]struct{})
    files := make(map[string]struct{})

    for _, f := range rc.File {
        dname, fname = filepath.Split(f.Name)
        if fname != "" {
            if fname == "classes.dex" {
                //normal = true
                dexsize = f.FileInfo().Size()
                if dexdir != "" {
                    extractFile(f, dexdir, md5)
                }
            } else if fname == "AndroidManifest.xml" {
                pkgname = getPkgname(f)
            } else if strings.Contains(dname, "META-INF") && strings.Contains(fname, ".") {
                fnameSplit := strings.Split(fname, ".")
                if fnameSplit[len(fnameSplit)-1] == "DSA" || fnameSplit[len(fnameSplit)-1] == "RSA" {
                    certmd5 = getMd5(f)
                }
            }
            files[fname] = struct{}{}
        }

        if dname != "" {
            dirs[dname] = struct{}{}
        }
    }
    //if !normal {
    //    return "", pkgname, dexsize, dirs, files
    //} else {
    return certmd5, pkgname, dexsize, dirs, files
    //}
}

func Worker(dexdir string, apkChan <-chan AppPath, resChan chan<- *Result, wg *sync.WaitGroup) {
    // Decreasing internal counter for wait-group as soon as goroutine finishes
    defer wg.Done()

    var certmd5, pkgname string
    var dexsize int64
    var dirs, files map[string]struct{}

    for apppath := range apkChan {
        certmd5, pkgname, dexsize, dirs, files = unzipApk(apppath.md5, dexdir, apppath.path)
        if certmd5 != "" && len(dirs) != 0 && len(files) != 0 {
            minfo, _ := json.Marshal(&MetaInfo{certmd5, pkgname, dexsize, dirs, files})
            resChan <- &Result{[]byte("m-"+apppath.md5), &minfo}
        }
    }
}

func main() {
    //Initialization
    flag.Parse()
    if md5apk == "" || dbname == "" {
        Usage()
        os.Exit(1)
    }

    logFile, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalln("Failed to open log file", err)
    }
    logHandle := io.MultiWriter(logFile, os.Stdout)
    Init(logHandle)
    Info.Println("Meta info collection start")

    //if _, err := os.Stat(objname); err == nil { 
    //    load(objname, &metamap)
    //}
    //defer store(objname, metamap)

    //fmt.Println("size:", len(metamap))
    //for md5, _ := range metamap {
    //    fmt.Println(md5) 
    //}
    wg := new(sync.WaitGroup)
    apkChan := make(chan AppPath, 10000)
    resChan := make(chan *Result, 10000)
    // Adding routines to workgroup and running then
    for i := 0; i < runtime.NumCPU()-2; i++ {
        wg.Add(1)
        go Worker(dexdir, apkChan, resChan, wg)
    }
    db, _ := leveldb.OpenFile(dbname, nil)
    defer db.Close()
    go func() {
        for result := range resChan {
            //metamap[result.md5] = result.minfo
            db.Put(result.md5, *result.minfo, nil) 
        }
    }()

    fin, _ := os.Open(md5apk)
    defer fin.Close()
    scanner := bufio.NewScanner(fin)
    var lineSplit []string
    for scanner.Scan() {
        lineSplit = strings.Split(scanner.Text(), ": ")
        if _, ok := metamap[lineSplit[0]]; !ok {
            apkChan <- AppPath{lineSplit[0], lineSplit[1]}
        }
    }

    close(apkChan)
    wg.Wait()
    close(resChan)
    Info.Println("Program end")
}

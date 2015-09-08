package main

import (
    "fmt"
    "os"
    "io"
    "log"
    "flag"
    "strings"
    "runtime"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
)

var (
    Trace, Info, Warning, Error     *log.Logger
    logfile, dbname         string
)

func Usage() {
    fmt.Println("Fingerprint balanced bucket, store fhash within embeded db")
    fmt.Println("   Usage: generate -dbname=db")
}

func Init(errorHandle io.Writer) {
    Info = log.New(errorHandle,
        "INFO: ",
        log.Ldate|log.Ltime|log.Lshortfile)

    Error = log.New(errorHandle,
        "ERROR: ",
        log.Ldate|log.Ltime|log.Lshortfile)
}

func init() {
    runtime.GOMAXPROCS(runtime.NumCPU())
    //_, filename, _, _ := runtime.Caller(1)
    //cwd, _ := path.Split(filename)
    //libpath = path.Join(cwd, "libs")
    //os.Setenv("LD_LIBRARY_PATH", libpath)
    flag.StringVar(&dbname, "dbname", "db", "fingerprint db storage name")
    flag.StringVar(&logfile, "logfile", "entrycount.log", "file name for logging")
}

func main() {
    //Initialization
    flag.Parse()
    logFile, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalln("Failed to open log file", err)
    }
    logHandle := io.MultiWriter(logFile, os.Stdout)
    Init(logHandle)

    db, _ := leveldb.OpenFile(dbname, nil)
    defer db.Close()
    var key []byte
    var count int
    iter := db.NewIterator(util.BytesPrefix([]byte("h-")), nil)
    for iter.Next() {
        // Remember that the contents of the returned slice 
        // should not be modified, and only valid until the next call to Next.
        key = iter.Key()
        lognbit := strings.Split(string(key[:]), "-")[1]
        if lognbit != "Inf" {
            //fmt.Println(string(key[:]))
            count += 1
            //mapChan <- &Map{string(key[:]), &value}
        }
    }
    iter.Release()

    Info.Println("Total count", count)
}

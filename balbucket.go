package main

import (
    "fmt"
    "os"
    "io"
    "log"
    "flag"
    "math"
    "sync"
    "strings"
    "runtime"
    "hash/fnv"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
)

type Map struct {
    index  string
    fphash      *[]byte                     // Define as byte slice for easier db storage
}

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

func Worker(mapChan chan *Map, db *leveldb.DB, wg *sync.WaitGroup) {
    // Decreasing internal counter for wait-group as soon as goroutine finishes
    var fphash                  *[]byte
    var bucket                  float64
    var indexSplit              []string
    var index                   string

    defer wg.Done()

    for input := range mapChan {
        indexSplit = strings.Split(input.index, "-") 
        // FNV hash range [1, 2^32], divide into 2^4 buckets, each bucket has 2^28 unique values
        bucket = GetBucket(input.fphash)
        index = fmt.Sprintf("%.0f-%v-%v", bucket, indexSplit[2], indexSplit[3])
        //fmt.Println(index)
        //resChan <- &Result{index, md5, fphash, fpmap}
        //mapbyte, _ := json.Marshal(*fpmap)
        //    pkgbyte, _ := json.Marshal(*topPkgs)
        db.Put([]byte("h-"+index), *fphash, nil)
        //    db.Put([]byte("m-"+md5), mapbyte, nil)
        //    db.Put([]byte("p-"+md5+strconv.Itoa(numFunc)), pkgbyte, nil)
    }
}

func init() {
    runtime.GOMAXPROCS(runtime.NumCPU())
    //_, filename, _, _ := runtime.Caller(1)
    //cwd, _ := path.Split(filename)
    //libpath = path.Join(cwd, "libs")
    //os.Setenv("LD_LIBRARY_PATH", libpath)
    flag.StringVar(&dbname, "dbname", "db", "fingerprint db storage name")
    flag.StringVar(&logfile, "logfile", "balbucket.log", "file name for logging")
}

func GetBucket(fhash *[]byte) float64 {
    hasher32a := fnv.New32()
    hasher32a.Write(*fhash)
    out := hasher32a.Sum32()

    // FNV hash range [0, 2^32], divide into 16 bucket, each bucket has 2^28 unique values
    if out > 0 {
        return math.Ceil(float64(out)/float64(1<<28))
    } else {
        return float64(1)
    }
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
    Info.Println("Fingerprint generation started")

    wg := new(sync.WaitGroup)
    mapChan := make(chan *Map, 1000)
    db, _ := leveldb.OpenFile(dbname, nil)
    defer db.Close()

    // Adding routines to workgroup and running then
    for i := 0; i < runtime.NumCPU()-2; i++ {
        wg.Add(1)
        go Worker(mapChan, db, wg)
    }

    var key, value []byte
    var lognbit string 
    iter := db.NewIterator(util.BytesPrefix([]byte("h-")), nil)
    for iter.Next() {
        // Remember that the contents of the returned slice 
        // should not be modified, and only valid until the next call to Next.
        key = iter.Key()
        value = iter.Value()
        lognbit = strings.Split(string(key[:]), "-")[1]
        if lognbit != "Inf" {
            //fmt.Println(string(key[:]))
            mapChan <- &Map{string(key[:]), &value}
        }
    }
    iter.Release()

    close(mapChan)
    wg.Wait()
    Info.Println("Program end")
}

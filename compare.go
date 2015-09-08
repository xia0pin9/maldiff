package main

import (
    "fmt"
    "os"
    "io"
    "log"
    "sync"
    "flag"
    "bytes"
    "strconv"
    "strings"
    "runtime"
    "io/ioutil"
    "encoding/gob"
    "encoding/json"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
)

type KeyPair struct {
    bkey, mkey      []byte
    bmd5, mmd5      string
    bsize, msize    float64 
}

type MetaInfo struct {
    Certmd5, Pkgname string
    Dexsize    int64
    Dirs, Files     map[string]struct{} 
}

var (
    Trace, Info, Warning, Error             *log.Logger
    logfile, bendb, maldb, benmeta, malmeta, output  string
    threshold                               float64
    bitmap = make(map[uint]uint)
    benMetaMap = make(map[string]*MetaInfo)
    malMetaMap = make(map[string]*MetaInfo)
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
    fmt.Println("Fingerprint comparison, get candidate repackaging pairs")
    fmt.Println("   Usage: compare -maldb=maldb -bendb=bendb <-threshold=0.8>")
}

func init() {
    runtime.GOMAXPROCS(runtime.NumCPU())
    flag.StringVar(&bendb, "bendb", "", "db name where benign fingerprints are stored")
    flag.StringVar(&maldb, "maldb", "", "db name where malicious fingerprints are stored")
    flag.StringVar(&benmeta, "benmeta", "benmeta", "file name where benign meta info are stored")
    flag.StringVar(&malmeta, "malmeta", "malmeta", "file name where malicious meta info are stored")
    flag.StringVar(&output, "output", "candidate_output.txt", "file name for storing final output")
    flag.Float64Var(&threshold, "threshold", 0.85, "similarity threshold")
}

func load(fname string, e interface{}) {
    n,err := ioutil.ReadFile(fname)
    if err != nil { panic(err) }

    p := bytes.NewBuffer(n)
    dec := gob.NewDecoder(p)

    err = dec.Decode(e)
    if err != nil { panic(err) }
}

func bitcount(fhash []byte) uint {
    res := uint(0)
    for _, b := range fhash {
        res += bitmap[uint(b)]
    }
    return res
}

func loadbmap() {
    for i := uint(0); i <= 255; i++ {
        bitmap[i] = nb(i)
    }
}

func nb(val uint) uint {
    res := uint(0)
    for ; val != 0; {
        res += 1
        val &= val - 1
    }
    return res
}

func HashCompare(bhash, mhash []byte, bsize, msize float64) float64 {
    res := 0.0
    for i := 0; i < len(bhash); i ++ {
        res += float64(bitmap[uint(bhash[i])&uint(mhash[i])])
    }
    return res/(bsize + msize - res)
}

func SliceCompare(bset, mset []string) float64 {
    var res float64
    fmap := make(map[string]bool)

    if len(bset) <= len(mset) {
        for _, b := range bset {
            fmap[b] = true
        }
        for _, m := range mset {
            if fmap[m] {
                res += 1
            }
        }
    } else {
        for _, m := range mset {
            fmap[m] = true
        }
        for _, b := range bset {
            if fmap[b] {
                res += 1
            }
        }
    }
    return res/(float64(len(bset)+len(mset))-res)
}

func MapCompare(bset, mset map[string]struct{}) float64 {
    var res float64

    if len(bset) <= len(mset) {
        for b, _ := range bset {
            if _, ok := mset[b]; ok {
                res += 1
            }
        }
    } else {
        for m, _ := range mset {
            if _, ok := bset[m]; ok {
                res += 1
            }
        }
    }
    return res/(float64(len(bset)+len(mset))-res)
}

func levenshtein(s, t string) int {
    d := make([][]int, len(s)+1)
    for i := range d {
        d[i] = make([]int, len(t)+1)
    }
    for i := range d {
        d[i][0] = i
    }
    for j := range d[0] {
        d[0][j] = j
    }
    for j := 1; j <= len(t); j++ {
        for i := 1; i <= len(s); i++ {
            if s[i-1] == t[j-1] {
                d[i][j] = d[i-1][j-1]
            } else {
                min := d[i-1][j]
                if d[i][j-1] < min {
                    min = d[i][j-1]
                }
                if d[i-1][j-1] < min {
                    min = d[i-1][j-1]
                }
                d[i][j] = min + 1
            }
        }

    }
    return d[len(s)][len(t)]
}

func MetaCheck(benDB, malDB *leveldb.DB, bmd5, mmd5 string) bool {
    beninfo, bok := benMetaMap[bmd5]
    malinfo, mok := malMetaMap[mmd5]

    if bok && mok {
        if beninfo.Certmd5 == malinfo.Certmd5 {
            Info.Println("Metainfo: cert filtered", bmd5, mmd5)
            return false
        } else if beninfo.Dexsize < malinfo.Dexsize*2 && beninfo.Dexsize*2 > malinfo.Dexsize {
            Info.Println("Metainfo: dexsize", bmd5, mmd5)
            return true
        } else if beninfo.Pkgname != "" && malinfo.Pkgname != "" {
            if levenshtein(beninfo.Pkgname, malinfo.Pkgname) < 4 {
                Info.Println("Metainfo: pkgname", bmd5, mmd5)
                return true
            }
        } else if beninfo.Dirs != nil && malinfo.Dirs != nil {
            sim := MapCompare(beninfo.Dirs, malinfo.Dirs)
            if sim > 0.5 && sim < 2 {
                Info.Println("Metainfo: dirs", bmd5, mmd5)
                return true
            }
        } else if beninfo.Files != nil && malinfo.Files != nil {
            sim := MapCompare(beninfo.Files, malinfo.Files)
            if sim > 0.5 && sim < 2 {
                Info.Println("Metainfo: files", bmd5, mmd5) 
                return true
            }
        }
    }

    var bnumFunc, mnumFunc float64
    var bkey, mkey, bvalue, mvalue []byte
    var btopPkgs, mtopPkgs []string

    beniter := benDB.NewIterator(util.BytesPrefix([]byte("p-"+bmd5)), nil)
    for beniter.Next() {
        bkey = beniter.Key()
        bnumFunc, _ = strconv.ParseFloat(strings.Split(string(bkey[:]), "-")[2], 64)
        bvalue = beniter.Value()
        if err := json.Unmarshal(bvalue, &btopPkgs); err != nil {
            Error.Println("Unmarshal error", bmd5, err)
        }
    }
    defer beniter.Release()

    maliter := malDB.NewIterator(util.BytesPrefix([]byte("h-"+mmd5)), nil)
    for maliter.Next() {
        mkey = maliter.Key()
        mnumFunc, _ = strconv.ParseFloat(strings.Split(string(mkey[:]), "-")[2], 64)
        mvalue = maliter.Value()
        if err := json.Unmarshal(mvalue, &mtopPkgs); err != nil {
            Error.Println("Unmarshal error", mmd5, err)
        }
    }
    defer maliter.Release()

    if bnumFunc/mnumFunc < 2 && bnumFunc/mnumFunc > 0.5 {
        Info.Println("Metainfo: numfunc", bmd5, mmd5)
        return true
    } else {
        sim := SliceCompare(btopPkgs, mtopPkgs)
        if sim > 0.5 && sim < 2 {
            Info.Println("Metainfo: toppkgs", bmd5, mmd5)
            return true
        }
    }
    return false
}

func Worker(benDB, malDB *leveldb.DB, keysChan chan *KeyPair, resChan chan string, wg *sync.WaitGroup) {
    // Decreasing internal counter for wait-group as soon as goroutine finishes
    defer wg.Done()

    var score float64
    var bhash, mhash []byte

    for keyPair := range keysChan {
        // Todo: meta info check
        if MetaCheck(benDB, malDB, keyPair.bmd5, keyPair.mmd5) {
            bhash, _ = benDB.Get(keyPair.bkey, nil)
            mhash, _ = malDB.Get(keyPair.mkey, nil)
            score = HashCompare(bhash, mhash, keyPair.bsize, keyPair.msize)
            resChan <- fmt.Sprintf("%v, %v, %.3f\n", keyPair.bmd5, keyPair.mmd5, score) 
        }
    }
}

func GetPairs(benSize, malSize *map[string]float64, benKeys, malKeys *map[string][]byte, keysChan chan *KeyPair, wg *sync.WaitGroup) {
    defer wg.Done()
    for bmd5, bsize := range *benSize {
        for mmd5, msize := range *malSize {
            if threshold < bsize/msize && bsize/msize < 1/threshold {
                keysChan <- &KeyPair{(*benKeys)[bmd5], (*malKeys)[mmd5], bmd5, mmd5, bsize, msize}
            }
        }
    }
}

func main() {
    //Initialization
    flag.Parse()
    if bendb == "" || maldb == "" {
        Usage()
        os.Exit(1)
    }

    loadbmap()
    load(benmeta, &benMetaMap)
    load(malmeta, &malMetaMap)

    logFile, err := os.OpenFile("compare.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalln("Failed to open log file", err)
    }
    logHandle := io.MultiWriter(logFile, os.Stdout)
    Init(logHandle)
    Info.Println("Fingerprints comparison start")

    outFile, _ := os.Create(output)
    defer outFile.Close()
    benDB, _ := leveldb.OpenFile(bendb, nil)
    defer benDB.Close()
    malDB, _ := leveldb.OpenFile(maldb, nil)
    defer malDB.Close()

    var bKeySplit, mKeySplit    []string
    var bKey, mKey              []byte
    var bsize, msize            float64
    preMalKeys := make(map[string][]byte)
    preBenKeys := make(map[string][]byte)
    preMalSizes := make(map[string]float64)
    preBenSizes := make(map[string]float64)

    for i := 3; i <= 20; i ++ {
        curMalKeys := make(map[string][]byte)
        curBenKeys := make(map[string][]byte)
        curMalSizes := make(map[string]float64)
        curBenSizes := make(map[string]float64)

        beniter := benDB.NewIterator(util.BytesPrefix([]byte("h-"+strconv.Itoa(i))), nil)
        for beniter.Next() {
            bKey = beniter.Key()
            bKeySplit = strings.Split(string(bKey[:]), "-")
            bsize, _ = strconv.ParseFloat(bKeySplit[2], 64)
            curBenSizes[bKeySplit[3]] = bsize
            curBenKeys[bKeySplit[3]] = bKey
        }
        beniter.Release()

        maliter := malDB.NewIterator(util.BytesPrefix([]byte("h-"+strconv.Itoa(i))), nil)
        for maliter.Next() {
            mKey = maliter.Key()
            mKeySplit = strings.Split(string(mKey[:]), "-")
            msize, _ = strconv.ParseFloat(mKeySplit[2], 64)
            curMalSizes[mKeySplit[3]] = msize 
            curMalKeys[mKeySplit[3]] = mKey
        }
        maliter.Release()

        wg1 := new(sync.WaitGroup)
        wg2 := new(sync.WaitGroup)

        keysChan := make(chan *KeyPair, 10000)
        resChan := make(chan string, 10000)
        // Adding routines to workgroup and running then
        for i := 0; i < runtime.NumCPU()-4; i++ {
            wg1.Add(1)
            go Worker(benDB, malDB, keysChan, resChan, wg1)
        }

        wg2.Add(3)
        go GetPairs(&curBenSizes, &curMalSizes, &curBenKeys, &curMalKeys, keysChan, wg2)
        go GetPairs(&preBenSizes, &curMalSizes, &preBenKeys, &curMalKeys, keysChan, wg2)
        go GetPairs(&curBenSizes, &preMalSizes, &curBenKeys, &preMalKeys, keysChan, wg2)

        go func() {
            for result := range resChan {
                _, _ = outFile.WriteString(result)
            }
        }()

        wg2.Wait()
        close(keysChan)
        wg1.Wait()
        close(resChan)
        outFile.Sync()

        preBenSizes = curBenSizes
        preMalSizes = curMalSizes
        preBenKeys = curBenKeys
        preMalKeys = curMalKeys
    }

    Info.Println("Program end")
}

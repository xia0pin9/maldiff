package main

import (
    "fmt"
    "os"
    "io"
    "log"
    "sort"
    "flag"
    "path"
    "sync"
    "time"
    "bufio"
    "regexp"
    "strconv"
    "strings"
    "runtime"
    "os/exec"
    "encoding/json"
    "github.com/davecheney/profile"
    "github.com/syndtr/goleveldb/leveldb"
)


type Fpmap []Index

type Index struct {
    bindex, findex, cindex uint
}

type InputPair struct {
    mmd5    string
    bbits   map[uint]struct{}
}

var (
    Trace, Info, Warning, Error         *log.Logger
    logfile, libpath, inputlist, dexdir, diffdir, oridir, bendb, maldb  string
)

func Usage() {
    fmt.Println("Diff component extraction, store components in output dir")
    fmt.Println("   Usage: extract -dexdir=dexs -bendb=bendb -maldb=maldb <-output=diff> <-input=inlist>")
}

func Init(errorHandle io.Writer) {
    Info = log.New(errorHandle,
        "INFO: ",
        log.Ldate|log.Ltime|log.Lshortfile)

    Error = log.New(errorHandle,
        "ERROR: ",
        log.Ldate|log.Ltime|log.Lshortfile)
}

func Worker(indir, oridir, diffdir string, mdb *leveldb.DB, inChan chan InputPair, wg *sync.WaitGroup) {
    // Decreasing internal counter for wait-group as soon as goroutine finishes
    defer wg.Done()

    for inPair := range inChan {
        var fpmap Fpmap
        var indexList []Index

        data, _ := mdb.Get([]byte("m-"+inPair.mmd5), nil)
        if err := json.Unmarshal(data, &fpmap); err != nil {
            Error.Println("Error decoding fpmap object", inPair.mmd5)
        }
        for _, index := range fpmap {
            if _, ok := inPair.bbits[index.bindex]; !ok {
                indexList = append(indexList, index)
            }
        }
        indexMap := CombineIndexes(&indexList)
        go GetDiff(inPair.mmd5, indir, oridir, diffdir, indexMap)
    }
}

func GetDiff(md5, indir, oridir, diffdir string, indexMap map[uint][]int) {
    inpath := fmt.Sprintf("%s", path.Join(indir, md5+".dex"))
    command := fmt.Sprintf("%s -d -l plain %s", path.Join(libpath, "dexdump"), inpath)
    cmd := exec.Command("sh", "-c", command)
    out, err := cmd.StdoutPipe()
    done := make(chan error, 1)

    if err != nil {
        Error.Println("Error reading cmd", md5, err)
    }

    if err = cmd.Start(); err != nil {
        Error.Println("Error starting Cmd", md5, err)
    }

    fdiff, err := os.Create(path.Join(diffdir, md5))
    if err != nil {
        Error.Println("Error open diff file", md5, err)
    }
    fout, err := os.Create(path.Join(oridir, md5))
    if err != nil {
        Error.Println("Error open ori file", md5, err)
    }

    wdiff := bufio.NewWriter(fdiff)
    wori := bufio.NewWriter(fout)
    GetCode(out, wdiff, wori, indexMap)
    wdiff.Flush()
    wori.Flush()

    go func() {
        done <- cmd.Wait()
    }()
    select {
        case <-time.After(time.Second * 300):
            if err = cmd.Process.Kill(); err != nil {
                Error.Println("Failed to kill", err)
            }
            <-done
            Error.Println("Error exec time out ", md5)
        case err = <-done:
            if err != nil {
                Error.Println("Error waiting for Cmd", md5, err)
            }
    }
}

func GetCode(output io.ReadCloser, wdiff, wori *bufio.Writer, indexMap map[uint][]int) {
    var curCodes []string
    var curFname string
    var matched bool

    scanner := bufio.NewScanner(output)
    for scanner.Scan() {
        line := scanner.Text()
        wori.WriteString(line + "\n")
        if strings.HasPrefix(line, "Method(") {
            matched = true
            curCodes = nil
            curFname = line
        } else if line != "" {
            if line != "\"" {
                curCodes = append(curCodes, line) 
            }
        } else if matched {
            fOffset, _ := strconv.Atoi(regexp.MustCompile(`\d+`).FindString(curFname))
            if cindexes, ok := indexMap[uint(fOffset)]; ok {
                wdiff.WriteString(curFname + "\n")
                for _, cindex := range cindexes {
                    wdiff.WriteString(strconv.Itoa(cindex) + ": " + curCodes[cindex] + "\n")
                }
                wdiff.WriteString("\n")
            }
            matched = false
            curCodes = nil
        }
    }
}

func CombineIndexes(indexList *[]Index) map[uint][]int {
    res := make(map[uint][]int)

    for _, index := range *indexList {
        if _, ok := res[index.findex]; !ok {
            res[index.findex] = make([]int, 1)
        }
        res[index.findex] = append(res[index.findex], int(index.cindex))
    }

    for findex, cindexes := range res {
        sort.Ints(cindexes)
        res[findex] = cindexes
    }

    return res
}

func BitIndexes(bdb *leveldb.DB, bmd5s []string) map[uint]struct{} {
    wg := new(sync.WaitGroup)
    res := make(map[uint]struct{})
    bitChan := make(chan uint, 1000)

    go func() {
        for bit := range bitChan {
            if _, ok := res[bit]; !ok {
                res[bit] = struct{}{}
            }
        }
    }()

    for _, bmd5 := range bmd5s {
        wg.Add(1)
        go func(bmd5 string) {
            var fpmap Fpmap

            data, _ := bdb.Get([]byte("m-"+bmd5), nil)
            if err := json.Unmarshal(data, &fpmap); err != nil {
                Error.Println("Error decoding fpmap object", bmd5)
            }
            for _, index := range fpmap {
                bitChan <- index.bindex
            }
        }(bmd5)
    }
    wg.Wait()
    close(bitChan)
    return res
}

func init() {
    runtime.GOMAXPROCS(runtime.NumCPU())
    _, filename, _, _ := runtime.Caller(1)
    cwd, _ := path.Split(filename)
    libpath = path.Join(cwd, "libs")
    os.Setenv("LD_LIBRARY_PATH", libpath)
    flag.StringVar(&inputlist, "inputlist", "", "candidate repackaging pair list")
    flag.StringVar(&dexdir, "dexdir", "", "dex directory for selected malware list")
    flag.StringVar(&diffdir, "diffdir", "diffdir", "output dir for storing diff components")
    flag.StringVar(&oridir, "oridir", "oridir", "output dir for storing original components")
    flag.StringVar(&bendb, "bendb", "bendb", "db name where ben apps feature mapping are stored")
    flag.StringVar(&maldb, "maldb", "maldb", "db name where mal apps feature mapping are stored")
    flag.StringVar(&logfile, "logfile", "extract.log", "file name for loggging")
}

func main() {
    //Initialization
    flag.Parse()
    if dexdir == "" || inputlist == "" {
        Usage()
        os.Exit(1)
    }

    config := profile.Config{
        CPUProfile: false,
        MemProfile: false,
        BlockProfile: false,
    }
    defer profile.Start(&config).Stop()

    logFile, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalln("Failed to open log file", err)
    }
    logHandle := io.MultiWriter(logFile, os.Stdout)
    Init(logHandle)
    Info.Println("Diff component extraction started")

    malDB, _ := leveldb.OpenFile(maldb, nil)
    defer malDB.Close()
    benDB, _ := leveldb.OpenFile(bendb, nil)
    defer benDB.Close()

    wg := new(sync.WaitGroup)
    inChan := make(chan InputPair, 1000) 
    //Adding routines to workgroup and running then
    for i := 0; i < runtime.NumCPU()-2; i++ {
        wg.Add(1)
        go Worker(dexdir, diffdir, oridir, malDB, inChan, wg)
    }

    file, err := os.Open(inputlist)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    var lineSplit []string
    inputMap := make(map[string][]string)
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        // Format: benign md5, malicious md5, similarity score
        lineSplit = strings.Split(scanner.Text(), ", ")
        if _, ok := inputMap[lineSplit[1]]; !ok {
            inputMap[lineSplit[1]]= make([]string, 1)
        }
        inputMap[lineSplit[1]] = append(inputMap[lineSplit[1]], lineSplit[0])
    }

    for mmd5, bmd5s := range inputMap {
        bbits := BitIndexes(benDB, bmd5s)
        inChan <- InputPair{mmd5, bbits}
    }

    close(inChan)
    wg.Wait()
    Info.Println("Program end")
}

package main

import (
    "fmt"
    "os"
    "io"
    "log"
    "flag"
    "path"
    "math"
    "sync"
    "time"
    "bufio"
    "regexp"
    "strconv"
    "strings"
    "runtime"
    "io/ioutil"
    "os/exec"
    "encoding/json"
    "github.com/davecheney/profile"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
)


type Fpmap map[uint][]Index

type Index struct {
    findex, cindex int
}

type Result struct {
    index, md5  string
    fphash      *[]byte                     // Define as byte slice for easier db storage
    fpmap       *Fpmap
}

const    fpsize                     = 64    // fingerprint size in KB

var (
    Trace, Info, Warning, Error     *log.Logger
    logfile, libpath, dexdir, dbname         string
    ngsize                          int
)

var (
    BuiltinTypes = [...]string{"Z", "B", "C", "S", "I", "J", "F", "D", "V", "Ljava", "Landroid", "Ljavax", "Ljunit"}
    oneLevelLibs = make(map[string]bool)
    twoLevelLibs = make(map[string]map[string]bool)
    threeLevelLibs = make(map[string]map[string]bool)
    bitmap = make(map[uint]uint)
)

func Usage() {
    fmt.Println("Fingerprint generation, store fhash within embeded db")
    fmt.Println("   Usage: generate -dexdir=dexs -dbname=db <-ngsize=size>")
}

func Init(errorHandle io.Writer) {
    Info = log.New(errorHandle,
        "INFO: ",
        log.Ldate|log.Ltime|log.Lshortfile)

    Error = log.New(errorHandle,
        "ERROR: ",
        log.Ldate|log.Ltime|log.Lshortfile)
}

func Worker(indir string, md5Chan chan string, db *leveldb.DB, wg *sync.WaitGroup) {
    // Decreasing internal counter for wait-group as soon as goroutine finishes
    var out                     io.ReadCloser
    var topPkgs                 *map[string]struct{}
    var fphash                  *[]byte
    var fpmap                   *Fpmap
    var numFunc                 int
    var inpath, command, index  string
    var err                     error
    var nbit                    uint
    var nlogbit                 float64
    done := make(chan error, 1)

    defer wg.Done()

    for md5 := range md5Chan {
        inpath = fmt.Sprintf("%s", path.Join(indir, md5+".dex"))
        command = fmt.Sprintf("%s -d -l plain %s", path.Join(libpath, "dexdump"), inpath)
        cmd := exec.Command("sh", "-c", command)
        out, err = cmd.StdoutPipe()
        if err != nil {
            Error.Println("Error reading cmd", md5, err)
        }

        if err = cmd.Start(); err != nil {
            Error.Println("Error starting Cmd", err, md5)
        }

        numFunc, topPkgs, fphash, fpmap = GenerateHash(GetCode(out))

        go func() {
            done <- cmd.Wait()
        }()
        select {
            case <-time.After(time.Second * 180):
                if err = cmd.Process.Kill(); err != nil {
                    Error.Println("Failed to kill", err)
                }
                <-done
                Error.Println("Error exec time out ", md5)
            case err = <-done:
                if err != nil {
                    Error.Println("Error waiting for Cmd", err, md5)
                }
        }

        nbit = bitcount(*fphash)
        if nbit > 0 {
            nlogbit = math.Log2(float64(nbit)) + 1
            index = fmt.Sprintf("%.0f-%v-%v", nlogbit, nbit, md5)
            //fmt.Println(index)
            //resChan <- &Result{index, md5, fphash, fpmap}
            mapbyte, _ := json.Marshal(*fpmap)
            pkgbyte, _ := json.Marshal(*topPkgs)
            db.Put([]byte("h-"+index), *fphash, nil)
            db.Put([]byte("m-"+md5), mapbyte, nil)
            db.Put([]byte("p-"+md5+strconv.Itoa(numFunc)), pkgbyte, nil)
        } else {
            db.Put([]byte("h-Inf-0-"+md5), nil, nil)
            Info.Println("Empty fphash:", md5)
        }
    }
}

func GetCode(output io.ReadCloser) *map[string][]string {
    var curCodes, codelist, lineSplit []string
    var line, typeStr, curFname, opcode, operand, operandOri, value string
    var matched bool

    codeIndex := make(map[string][]string)
    //scanner := bufio.NewScanner(bytes.NewReader(*output))
    //for _, line := range strings.Split(output, "\n")  {
    scanner := bufio.NewScanner(output)
    for scanner.Scan() {
        line = scanner.Text()
        if starts(line, "Method(") {
            matched = true
            curCodes = nil
            curFname = line 
        } else if line != "" {
            //codelist := strings.Split(line, " ")
            opcode = strings.Split(line, " ")[0]
            codelist = strings.Split(line, ", ")
            operandOri = codelist[len(codelist)-1]
            operand = codelist[len(codelist)-1]

            if starts(opcode, "return") {
                curCodes = append(curCodes, opcode)
            } else if starts(opcode, "const") {
                if starts(opcode, "const-class") {
                    // We want to use builtin types (if any) as additional features
                    builtin := false
                    for ; string(operand[0]) == "["; {
                        operand = operand[1:]
                    }
                    for _, typeStr = range BuiltinTypes {
                        if starts(strings.Split(operand, "/")[0], typeStr) {
                            builtin = true
                            break
                        }
                    }
                    if builtin {
                        curCodes = append(curCodes, opcode + operandOri)
                    } else if starts(operandOri, "[") {
                        curCodes = append(curCodes, opcode + "[private;")
                    } else {
                        curCodes = append(curCodes, opcode + "private;")
                    }
                } else if starts(opcode, "const-string") {
                    // e.g., const-string v6, "contact_id = "
                    // e.g., const-string v1, ", blockId: "
                    lineSplit = strings.Split(line, ", \"")
                    operand = lineSplit[len(lineSplit) - 1]
                    value = strings.Trim(strings.Trim(operand, "\""), "'")
                    curCodes = append(curCodes, opcode + value)
                } else {
                    curCodes = append(curCodes, opcode)
                }
            } else if starts(opcode, "invoke") {
                if !ends(opcode, "-quick") {
                    var fInSig, fInSigStr, fOutSig, fOutSigStr, fName string

                    // Get func name
                    builtin := false
                    fTop := strings.Split(operand, "/")[0]
                    for _, typeStr = range BuiltinTypes {
                        if starts(typeStr, "L") && starts(fTop, typeStr) {
                            builtin = true
                            break
                        }
                    }
                    // e.g., invoke-virtual {v12}, Ljava/lang/Exception;.printStackTrace:()V
                    if builtin && in(operand, ".") && in(operand, ":") {
                        fName = strings.Split(strings.Split(operand, ".")[1], ":")[0]
                    } else {
                        fName = "func"
                    }

                    // Get func input type info
                    if in(operand, "(") && in(operand, ")") {
                        fInSigStr = operand[strings.Index(operand, "(")+1: strings.Index(operand, ")")]
                    }
                    // e.g., (IILandroid/graphics/Bitmap$Config;)
                    if in(fInSigStr, ";") {
                        for ; len(fInSigStr) > 0; {
                            iSig := string(fInSigStr[0])
                            if iSig != "L" {
                                fInSig += string(fInSigStr[0])
                                fInSigStr = fInSigStr[1:] 
                            } else {
                                iSigStr := fInSigStr[0: strings.Index(fInSigStr, ";") + 1]
                                //fmt.Println("test:" + fInSigStr + ", " + iSig + ", " + iSigStr)
                                builtin := false
                                for _, typeStr = range BuiltinTypes {
                                    if starts(typeStr, "L") && starts(iSigStr, typeStr) {
                                        builtin = true
                                        break
                                    }
                                }
                                if builtin {
                                    fInSig += iSigStr
                                } else {
                                    fInSig += "private;"
                                }
                                fInSigStr = fInSigStr[strings.Index(fInSigStr, ";") + 1:]
                            }
                        }
                    } else {
                        fInSig = fInSigStr
                    }

                    // Get func output type info
                    if in(operand, ")") {
                        fOutSigStr = operand[strings.Index(operand, ")")+1:]
                    }
                    fOutSigOri := fOutSigStr
                    builtin = false
                    if len(fOutSigStr) > 0 {
                        for ; string(fOutSigStr[0]) == "["; {
                            fOutSigStr = fOutSigStr[1:]
                        }
                        for _, typeStr = range BuiltinTypes {
                            if starts(strings.Split(fOutSigStr, "/")[0], typeStr) {
                                builtin = true 
                                break
                            }
                        }
                        if builtin {
                            fOutSig = fOutSigOri
                        } else if starts(fOutSigOri, "[") {
                            fOutSig = "[private;"
                        } else {
                            fOutSig = "private;"
                        }
                    }
                    curCodes = append(curCodes, opcode + fName + "(" + fInSig + ")" + fOutSig)
                } else {
                    curCodes = append(curCodes, opcode)
                }
            } else if starts(opcode, "iget") || starts(opcode, "iput") || starts(opcode, "sget") || starts(opcode, "sput") {
                if !ends(opcode, "-quick") {
                    if operand == "" {
                        curCodes = append(curCodes, opcode)
                    } else {
                        // e.g., iget v4, v3, Landroid/graphics/Rect;.top:I
                        operandSplit := strings.Split(operand, ":")
                        operand = operandSplit[len(operandSplit)-1]
                        operandOri = operand
                        builtin := false 

                        for ; string(operand[0])== "["; {
                            operand = operand[1:]
                        }
                        for _, typeStr = range BuiltinTypes {
                            if starts(strings.Split(operand, "/")[0], typeStr) {
                                builtin = true
                                break
                            }
                        }
                        if builtin {
                            curCodes = append(curCodes, opcode + operandOri)
                        } else if starts(operandOri, "["){
                            curCodes = append(curCodes, opcode +"[private;")
                        } else {
                            curCodes = append(curCodes, opcode + "private;")
                        }
                    }
                } else {
                    curCodes = append(curCodes, opcode)
                }
            } else if starts(opcode, "check-cast") || starts(opcode, "instance-of") || starts(opcode, "new-instance") || starts(opcode, "new-array") {
                operandOri = operand
                builtin := false

                for ; string(operand[0]) == "["; {
                    operand = operand[1:]
                }
                for _, typeStr = range BuiltinTypes {
                    if starts(strings.Split(operand, "/")[0], typeStr) {
                        builtin = true
                        break
                    }
                }
                if builtin {
                    curCodes = append(curCodes, opcode + operandOri)
                } else if starts(operandOri, "[") {
                    curCodes = append(curCodes, opcode + "[private;")
                } else {
                    curCodes = append(curCodes, opcode + "private;")
                }
            } else if starts(opcode, "fill-array-data-payload") {
                value = strings.Trim(strings.Trim(operand, "\""), "'")
                curCodes = append(curCodes, opcode + value)
            } else if in(opcode, "-switch-data") {
                // make it consistent with androguard
                curCodes = append(curCodes, strings.Replace(opcode, "-data", "-payload", -1))
            } else if line == "\"" {
                // String split hack
                continue
            } else {
                curCodes = append(curCodes, opcode)
            }
        } else if matched {
            matched = false
            if len(curCodes) > 0 {
                codeIndex[curFname] = curCodes
            }
            curCodes = nil
        }
    }

    return &codeIndex
}

func GenerateHash(codeList *map[string][]string) (int, *map[string]struct{}, *[]byte, *Fpmap) {
    //var fhash [fpsize*1024]byte 
    var fnameSplit, bytecodes []string
    var numFunc, fOffset    int
    var index, i, j         uint
    var builtin, libcode    bool
    var typeStr, fname, topname, secondname, thirdname, nameindex, feature string

    fhash := make([]byte, fpsize*1024, fpsize*1024)
    fpmap := make(Fpmap)
    topPkgs := make(map[string]struct{})

    for fname, bytecodes = range *codeList {
        numFunc += 1
        fOffset, _ = strconv.Atoi(regexp.MustCompile(`\d+`).FindString(fname))
        fname = strings.Split(fname, "): ")[1]
        fnameSplit = strings.Split(fname, ".")
        //topPkgs = append(topPkgs, fnameSplit[0])
        topPkgs[fnameSplit[0]] = struct{}{}

        builtin = false
        for _, typeStr = range BuiltinTypes {
            if string(typeStr[0]) == "L" && fnameSplit[0] == typeStr {
                builtin = true
                break
            }
        }

        libcode = builtin
        if !libcode {
            if oneLevelLibs[fnameSplit[0]] {
                libcode = true
            } else if len(fnameSplit) >= 2 {
                topname, secondname = fnameSplit[0], fnameSplit[1]
                if _, ok := twoLevelLibs[topname]; ok {
                    if twoLevelLibs[topname][secondname] {
                        libcode = true
                    }
                }
                if !libcode && len(fnameSplit) >= 3 {
                    thirdname = fnameSplit[2]
                    nameindex = topname + secondname
                    if _, ok := threeLevelLibs[nameindex]; ok {
                        if threeLevelLibs[nameindex][thirdname] {
                            libcode = true
                        }
                    }
                }
            }
        }

        if ngsize < len(bytecodes) {
            for k := 0; k < len(bytecodes) - ngsize + 1; k++ {
                feature = strings.Join(bytecodes[k:k + ngsize], "")
                //fmt.Println(feature)
                index = djb2([]byte(feature))
                if _, ok := fpmap[index]; !ok {
                    fpmap[index] = make([]Index, 1)
                }
                fpmap[index] = append(fpmap[index], Index{fOffset, k})
                if !libcode {
                    i = index >> 3
                    j = 1 << (uint)(index & 7)
                    fhash[i] |= byte(j)
                }
            }
        } else if ngsize == len(bytecodes) {
            feature = strings.Join(bytecodes, "")
            //fmt.Println(feature)
            index = djb2([]byte(feature))
            if _, ok := fpmap[index]; !ok {
                fpmap[index] = make([]Index, 1)
            }
            fpmap[index] = append(fpmap[index], Index{fOffset, 0})
            if !libcode {
                i = index >> 3
                j = 1 << (uint)(index & 7)
                fhash[i] |= byte(j)
            }
        }
    }

    return numFunc, &topPkgs, &fhash, &fpmap
}

func djb2(str []byte) uint {
    hash := uint(5381)
    for _, b := range str {
        hash = (((hash << 5) + hash) + uint(b)) % (fpsize * 1024 * 8)
    }
    return hash
}

func in(str, substr string) bool {
    return strings.Contains(str, substr)
}

func starts(str, substr string) bool {
    return strings.HasPrefix(str, substr)
}

func ends(str, substr string) bool {
    return strings.HasSuffix(str, substr)
}

func init() {
    runtime.GOMAXPROCS(runtime.NumCPU())
    _, filename, _, _ := runtime.Caller(1)
    cwd, _ := path.Split(filename)
    libpath = path.Join(cwd, "libs")
    os.Setenv("LD_LIBRARY_PATH", libpath)
    flag.StringVar(&dexdir, "dexdir", "", "dex file directory")
    flag.StringVar(&dbname, "dbname", "db", "fingerprint db storage name")
    flag.IntVar(&ngsize, "ngsize", 5, "N-gram size")
    flag.StringVar(&logfile, "logfile", "generate.log", "file name for logging")
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

func loadLibs(libpath string) {
    var lineSplit []string

    file, err := os.Open(path.Join(libpath, "third_party_libs.txt"))
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        if starts(line, "#") {
            continue
        } else if in(line, "/") {
            lineSplit = strings.Split(line, "/")
            if len(lineSplit) == 2 {
                top, second := lineSplit[0], lineSplit[1]
                if _, ok := twoLevelLibs[top]; !ok {
                    twoLevelLibs[top] = make(map[string]bool)
                }
                twoLevelLibs[top][second] = true
            } else {
                top, second, third := lineSplit[0], lineSplit[1], lineSplit[2]
                if _, ok := threeLevelLibs[top+second]; !ok {
                    threeLevelLibs[top+second] = make(map[string]bool)
                }
                threeLevelLibs[top+second][third] = true
            }
        } else {
            oneLevelLibs[line] = true
        }
    }
}

func main() {
    //Initialization
    flag.Parse()
    if dexdir == "" {
        Usage()
        os.Exit(1)
    }

    loadLibs(libpath)
    loadbmap()

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
    Info.Println("Fingerprint generation started")

    db, _ := leveldb.OpenFile(dbname, nil)
    defer db.Close()

    finishedMd5s := make(map[string]struct{})
    iter := db.NewIterator(util.BytesPrefix([]byte("h-")), nil)
    for iter.Next() {
        // Remember that the contents of the returned slice 
        // should not be modified, and only valid until the next call to Next.
        key := iter.Key()
        if string(key[:]) != "" {
            md5 := strings.Split(string(key[:]), "-")[3]
            //fmt.Println(string(key[:]))
            finishedMd5s[md5] = struct{}{}
        }
    }
    iter.Release()

    md5Chan := make(chan string, 10000)
    wg := new(sync.WaitGroup)

    // Adding routines to workgroup and running then
    for i := 0; i < runtime.NumCPU(); i++ {
        wg.Add(1)
        go Worker(dexdir, md5Chan, db, wg)
    }

    dexs, _ := ioutil.ReadDir(dexdir)
    for _, dex := range dexs {
        md5 := strings.Split(dex.Name(), ".")[0]
        if _, ok := finishedMd5s[md5]; !ok {
            md5Chan <- md5
        }
    }

    close(md5Chan)
    wg.Wait()
    Info.Println("Program end")
}

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/user"
	"strings"
)

//_Mark 一条密码记录
type _Mark struct {
	hst string
	nme string
	p33 string
}

type Pa33wd struct {
	_p33 []byte
	_db map[string]map[string]string
}

//isExist
func isExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

//curUsr 当前用户密码保存路径
func curUsr() string{
	usr, err := user.Current()
	if err != nil {
		os.Exit(-1)
	}
	return usr.HomeDir + string(os.PathSeparator) + ".p33"
}

func grs() []byte {
	bs := make([]byte, 32)
	for i:=0; i<32; i++ {
		bs[i] = uint8(rand.Uint32() % 256)
	}
	return bs
}


//使用PKCS7进行填充
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext) % blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}


func aesEncode(s, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//填充原文
	blockSize := block.BlockSize()
	s = PKCS7Padding(s, blockSize)
	//初始向量IV必须是唯一，但不需要保密
	cipherText := make([]byte, blockSize+len(s))
	//block大小 16
	iv := key[:blockSize]
	//block大小和初始向量大小一定要一致
	mode := cipher.NewCBCEncrypter(block,iv)
	mode.CryptBlocks(cipherText[blockSize:], s)
	return base64.StdEncoding.EncodeToString(cipherText)
}

func aesDecode(s []byte, key []byte) []byte  {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()
	if len(s) < blockSize {
		panic("ciphertext too short")
	}
	iv := key[:blockSize]
	s = s[blockSize:]
	// CBC mode always works in whole blocks.
	if len(s)%blockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(s, s)
	//解填充
	return PKCS7UnPadding(s)
}

// 当前用户主目录
var pth = curUsr()
// 密钥文件
var pf = pth + string(os.PathSeparator) + "sec.p33"
// 加密后的密码文件
var pdb = pth + string(os.PathSeparator) + "pa33.db"

func NewPa33wd() * Pa33wd {
	var err error
	if !isExist(pth) {
		err = os.Mkdir(pth, os.ModeSetuid)
		if err != nil {
			fmt.Printf("mkdir: %s failed\n", pth)
			os.Exit(-1)
		}
	}
	if !isExist(pf) && isExist(pdb){
		fmt.Printf("sec.p33 file not found\n")
		os.Exit(-1)
	}
	bs := make([]byte, 32)
	if !isExist(pf) {
		bs = grs()
		err := ioutil.WriteFile(pf, bs, os.ModeSetuid)
		if err!=nil {
			panic("create file " + pf + " failed")
		}
	} else {
		bs, err = ioutil.ReadFile(pf)
		if err!=nil {
			panic("read file " + pf + " failed")
		}
	}
	db := make(map[string]map[string]string)
	if isExist(pdb) {
		f,_ := os.Open(pdb)
		rd := bufio.NewReader(f)
		for  {
			ln, _e := rd.ReadString('\n')
			_m := make(map[string]map[string]string)
			ln  =  strings.Trim(ln, "\n")
			if len(ln) <=0 {
				break
			} else {
				lb, _ := base64.StdEncoding.DecodeString(ln)
				_ = json.Unmarshal(aesDecode(lb, bs), &_m)
				for k, v := range _m {
					db[k] = v
				}
			}
			if _e == io.EOF {
				break
			}
		}
	}
	return &Pa33wd{_p33: bs, _db: db}
}

func (p33 *Pa33wd) wrToFile() {
	f,e := os.OpenFile(pdb, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, os.ModeSetuid)
	if e!=nil {
		panic(e)
	}
	defer f.Close()
	for k,v := range p33._db {
		ln,_ := json.Marshal(map[string]map[string]string{k: v})
		_,_ = f.WriteString(aesEncode(ln, p33._p33) + "\n")
	}
}

func (p33 *Pa33wd) sv(mrk _Mark) {
	if mrk.hst == "" || mrk.nme == "" {
		fmt.Printf("host: %s; name: %s;\n", mrk.hst, mrk.nme)
		panic("host or name can not be empty")
	}
	_, ok := p33._db[mrk.hst]
	if ok {
		p33._db[mrk.hst][mrk.nme] = mrk.p33
	} else {
		p33._db[mrk.hst] = map[string]string{mrk.nme: mrk.p33}
	}
}

func (p33 *Pa33wd) del(mrk _Mark) {
	if mrk.hst == "" || mrk.nme == "" {
		fmt.Printf("host: %s; name: %s;\n", mrk.hst, mrk.nme)
		panic("host or name can not be empty")
	}
	_, ok := p33._db[mrk.hst]
	if ok {
		delete(p33._db[mrk.hst], mrk.nme)
		if len(p33._db[mrk.hst])==0 {
			delete(p33._db, mrk.hst)
		}
	}
}

func (p33 *Pa33wd) gp(mrk _Mark) []string {
	var rs []string
	if len(mrk.hst) < 4 {
		fmt.Printf("please support more infomations")
		return rs
	}
	for k,v := range p33._db {
		if strings.Contains(k, mrk.hst) {
			if len(mrk.nme)>0 {
				for n, p := range v {
					if strings.Contains(n, mrk.nme) {
						rs = append(rs, k + " -> " + n + ": " + p)
					}
				}
			} else {
				for n, p := range v {
					rs = append(rs, k + " -> " + n + ": " + p)
				}
			}
		}
	}
	return rs
}

func (p33 *Pa33wd) impt(file string)  {
	if !isExist(file) {
		panic("file: " + file + " not found")
	}
	f,_ := os.Open(file)
	rd := bufio.NewReader(f)
	for  {
		ln, _e := rd.ReadString('\n')
		ln  =  strings.Trim(ln, "\r\n")
		if len(ln) <=0 {
			break
		} else {
			cs := strings.Split(ln, ",")
			if cs[0]=="" || cs[2]=="" {
				continue
			}
			p33.sv(_Mark{
				hst: cs[0],
				nme: cs[2],
				p33: cs[3],
			})
		}
		if _e == io.EOF {
			break
		}
	}
	p33.wrToFile()
}

func usage()  {
	print("usage:\n")
	// save data
	print("pa33.exe xxx.com xxx xxx\n")
	// get data
	print("pa33.exe xxx.com xxx\n")
	// get data
	print("pa33.exe xxx.com\n")
	// import data
	print("pa33.exe -i xxx.csv. (only csv file)\n")
	// delete data
	print("pa33.exe -d xxx.com xxx\n")
}

func main() {
	al := len(os.Args)
	if al < 2 {
		usage()
		os.Exit(0)
	}
	var rs []string
	p33 := NewPa33wd()
	var mrk _Mark
	switch al {
	case 2:
		mrk = _Mark{
			hst: os.Args[1],
		}
		rs = p33.gp(mrk)
		break
	case 3:
		if os.Args[1]=="-i" {
			p33.impt(os.Args[2])
			fmt.Println("import data success.")
		} else {
			mrk = _Mark{
				hst: os.Args[1],
				nme: os.Args[2],
			}
			rs = p33.gp(mrk)
		}
		break
	case 4:
		if os.Args[1]=="-d" {
			mrk = _Mark{
				hst: strings.TrimSpace(os.Args[2]),
				nme: strings.TrimSpace(os.Args[3]),
			}
			p33.del(mrk)
			p33.wrToFile()
			fmt.Println("delete success.")
		}else{
			mrk = _Mark{
				hst: strings.TrimSpace(os.Args[1]),
				nme: strings.TrimSpace(os.Args[2]),
				p33: strings.TrimSpace(os.Args[3]),
			}
			p33.sv(mrk)
			p33.wrToFile()
			fmt.Println("save success.")
		}
		break
	default:
		usage()
		os.Exit(-1)
	}
	for _,s := range rs {
		fmt.Println(s)
	}
}
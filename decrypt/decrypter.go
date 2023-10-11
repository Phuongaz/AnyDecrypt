package decrypt

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

const TOKEN_FILE = "token.json"
const KEYS_FILE = "keys.db"

func cfb_decrypt(data []byte, key []byte) ([]byte, error) {
	b, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	shift_register := append(key[:16], data...)
	_tmp := make([]byte, 16)
	off := 0
	for off < len(data) {
		b.Encrypt(_tmp, shift_register)
		data[off] ^= _tmp[0]
		shift_register = shift_register[1:]
		off++
	}
	return data, nil
}

type ContentEntry struct {
	Path string `json:"path"`
	Key  string `json:"key"`
}

type ContentJson struct {
	Content []ContentEntry `json:"content"`
}

func decrypt_pack(pack_zip []byte, filename, key string) error {
	r := bytes.NewReader(pack_zip)
	z, err := zip.NewReader(r, r.Size())
	if err != nil {
		return err
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	defer f.Close()
	defer zw.Close()

	written := make(map[string]interface{})

	var content ContentJson
	{
		ff, err := z.Open("contents.json")
		if err != nil {
			if os.IsNotExist(err) {
				content = ContentJson{}
			} else {
				return err
			}
		} else {
			buf, _ := io.ReadAll(ff)
			dec, _ := cfb_decrypt(buf[0x100:], []byte(key))
			dec = bytes.Split(dec, []byte("\x00"))[0]
			fw, _ := zw.Create("contents.json")
			fw.Write(dec)
			if err := json.Unmarshal(dec, &content); err != nil {
				return err
			}
			written["contents.json"] = true
		}
	}

	for _, entry := range content.Content {
		ff, _ := z.Open(entry.Path)
		buf, _ := io.ReadAll(ff)
		if entry.Key != "" {
			buf, _ = cfb_decrypt(buf, []byte(entry.Key))
		}
		if len(buf) == 0 {
			continue
		}

		fw, _ := zw.Create(entry.Path)
		fw.Write(buf)
		written[entry.Path] = true
	}

	for _, src_file := range z.File {
		if written[src_file.Name] == nil {
			zw.Copy(src_file)
		}
	}

	return nil
}

func dump_keys(host string, keys map[string]string) {
	f, err := os.OpenFile(host+"/"+KEYS_FILE, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for uuid, key := range keys {
		f.WriteString(uuid + "=" + key + "\n")
	}
}

func download_pack(pack *resource.Pack) ([]byte, error) {
	buf := make([]byte, pack.Len())
	off := 0
	for {
		n, err := pack.ReadAt(buf[off:], int64(off))
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		off += n
	}
	return buf, nil
}

var pool = packet.NewClientPool()

func PacketLogger(header packet.Header, payload []byte, src, dst net.Addr) {
	var pk packet.Packet
	buf := bytes.NewBuffer(payload)
	r := protocol.NewReader(buf, 0, false)
	pkFunc, ok := pool[header.PacketID]
	if !ok {
		pk = &packet.Unknown{PacketID: header.PacketID}
	}
	pk = pkFunc()
	pk.Marshal(r)
	dir := "<-C"
	if strings.HasPrefix(strings.Split(src.String(), ":")[1], "19132") {
		dir = "S->"
	}
	fmt.Printf("P: %s 0x%x, %s\n", dir, pk.ID(), reflect.TypeOf(pk))
	switch p := pk.(type) {
	case *packet.ResourcePackDataInfo:
		fmt.Printf("info %s\n", p.UUID)
	}
}

func start(target string) []string {
	var save_encrypted bool
	var debug bool

	if target == "" {
		reader := bufio.NewReader(os.Stdin)
		target, _ = reader.ReadString('\n')
		target = strings.Replace(target, "\n", "", -1)
		target = strings.Replace(target, "\r", "", -1)
	}
	if len(strings.Split(target, ":")) == 1 {
		target += ":19132"
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid target: %s\n", err)
		os.Exit(1)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	var serverConn *minecraft.Conn

	go func() {
		<-sigs
		if serverConn != nil {
			serverConn.Close()
			serverConn = nil
		}
		cancel()
		os.Exit(0)
	}()

	var packet_func func(header packet.Header, payload []byte, src, dst net.Addr) = nil
	if debug {
		packet_func = PacketLogger
	}

	log := log.New(os.Stdout, "Decrypter: ", log.LstdFlags)

	if err := InitializeToken(log); err != nil {
		panic(err)
	}

	log.Printf("Connecting to %s\n", target)
	serverConn, err = minecraft.Dialer{
		TokenSource: TokenSrc,
		ClientData:  login.ClientData{},
		PacketFunc:  packet_func,
	}.DialContext(ctx, "raknet", target)
	if err != nil {
		panic(err)
	}

	defer func() {
		if serverConn != nil {
			serverConn.Close()
			serverConn = nil
		}
	}()

	if err := serverConn.DoSpawnContext(ctx); err != nil {
		panic(err)
	}

	log.Println("Connected")

	if len(serverConn.ResourcePacks()) > 0 {
		log.Println("ripping Resource Packs")
		os.Mkdir(host, 0777)

		keys := make(map[string]string)
		paths := make([]string, 0)
		for _, pack := range serverConn.ResourcePacks() {
			keys[pack.UUID()] = pack.ContentKey()
			log.Printf("ResourcePack(Id: %s Key: %s | Name: %s Version: %s)\n", pack.UUID(), keys[pack.UUID()], pack.Name(), pack.Version())

			pack_data, err := download_pack(pack)
			if err != nil {
				panic(fmt.Errorf("failed to download pack: %s", err))
			}
			if save_encrypted {
				os.WriteFile(host+"/"+pack.Name()+".ENCRYPTED.zip", pack_data, 0666)
			}
			log.Println("Decrypting...")
			path := host + "/" + pack.Name() + ".zip"
			if err := decrypt_pack(pack_data, path, keys[pack.UUID()]); err != nil {
				panic(fmt.Errorf("failed to decrypt %s: %s", pack.Name(), err))
			}
			paths = append(paths, path)
		}
		log.Printf("Writing keys to %s\n", KEYS_FILE)
		dump_keys(host, keys)

		return paths
	} else {
		log.Println("No Resourcepack sent")
	}
	log.Println("Done!")
	return nil
}

func Decrypt(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad IP"))
		return
	}
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "19132"
	}
	paths := start(ip + ":" + port)
	if len(paths) > 0 {
		err := zipFiles(ip+".zip", paths)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename="+ip+".zip")
		http.ServeFile(w, r, ip+".zip")
	} else {
		w.WriteHeader(404)
	}
}

func zipFiles(zipFileName string, files []string) error {
	zipFile, err := os.Create(zipFileName)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer file.Close()

		fileInfo, err := file.Stat()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(fileInfo)
		if err != nil {
			return err
		}

		header.Name = fileInfo.Name()
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, file)
		if err != nil {
			return err
		}
	}

	return nil
}

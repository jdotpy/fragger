package main

import "os"
import "io"
import "log"
import "fmt"
import "strings"
import "strconv"
import "io/ioutil"
import "math/rand"
import "encoding/hex"
import "path/filepath"
import "crypto/sha256"


const DEFAULT_CHUNK_SIZE = 1000000
const BUFFER_SIZE int = 16000
const FILE_WRITE_PERM = 0755
const ACTIVE_FILE_NAME = "fragging.frag"

func get_file(source string, write bool) *os.File {
  var source_file *os.File
  if source == "-" {
    if write {
      source_file = os.Stdout
    } else {
      source_file = os.Stdin
    }
  } else {
    var f *os.File
    var err error
    if write {
      f, err = os.Create(source)
    } else {
      f, err = os.Open(source)
    }
    source_file = f
    if err != nil {
      log.Fatal(err);
    }
  }
  return source_file
}

func read_string_from_file(source *os.File) string {
  file_bytes, err := ioutil.ReadAll(source)
  if err != nil && err != io.EOF {
    log.Fatal(err)
  }
  return string(file_bytes[:])
}

func sha_file(source *os.File) string {
	hasher := sha256.New()
  buffer := make([]byte, BUFFER_SIZE, BUFFER_SIZE)
  for {
    _, err := source.Read(buffer)
    if err == io.EOF {
      break;
    } else if err != nil {
      log.Fatal(err);
    }
    hasher.Write(buffer);
  }
  hash_bytes := hasher.Sum(nil)
  return hex.EncodeToString(hash_bytes)
}

func command_hash(source string, target string) {
  source_file := get_file(source, false)
  target_file := get_file(target, true)
  hash := sha_file(source_file)
  hash_hex_bytes := []byte(hash)
  _, err := target_file.Write(hash_hex_bytes)
  if (err != nil) {
    log.Fatal(err);
  }

  if (source != "-") {
    source_file.Close();
  }
  if (target != "-") {
    target_file.Close();
  }
}

func command_verify(payload_source string, hash_source string) {
  payload_file := get_file(payload_source, false)
  hash_file := get_file(hash_source, false)

  actual_hash := strings.TrimSpace(sha_file(payload_file))
  expected_hash := strings.TrimSpace(read_string_from_file(hash_file))
  if actual_hash != expected_hash {
    fmt.Printf("Expected:\n'%v'\ngot:\n'%v'", expected_hash, actual_hash)
    os.Exit(1)
  }
}

func command_frag(source string, target string, chunk_size int) {
  target_dir := filepath.Dir(target)
  active_file_name := filepath.Join(target_dir, strconv.Itoa(rand.Int()) + ".fragging")
  source_file := get_file(source, false)
  active_file := get_file(active_file_name, true)

  chunk_bytes_left := chunk_size
  global_hasher := sha256.New()
	frag_hasher := sha256.New()
  buffer := make([]byte, BUFFER_SIZE, BUFFER_SIZE)
  for {
    var read_slice []byte
    if chunk_bytes_left >= BUFFER_SIZE {
      read_slice = buffer
    } else {
      read_slice = buffer[:chunk_bytes_left]
    }
    bytes_read, err := source_file.Read(read_slice)
    chunk_bytes_left -= bytes_read
    global_hasher.Write(buffer)
    frag_hasher.Write(buffer)
    active_file.Write(buffer)
    if err == io.EOF || chunk_bytes_left == 0 {
      // pull out hash and reset hasher for next fragment 
      hash := hex.EncodeToString(frag_hasher.Sum(nil))
      frag_hasher.Reset();
      // Reset the active file renaming the existing one to the new fragment and truncating the active one
      active_file.Close()
      frag_file_name := filepath.Join(target_dir, hash + ".frag")
      os.Rename(active_file_name, frag_file_name)
      if err != io.EOF {
        active_file = get_file(active_file_name, true)
      }
    }
    if err == io.EOF {
      // If we actually hit the end of the file there are no more chunks
      break;
    }
  }
}

func main() {
  // Parse command
  args := os.Args[1:]
  if (len(args) < 1) {
    fmt.Printf("Please provide command")
    os.Exit(2)
  }

  switch(args[0]) {
    case "hash":
      if len(args) < 2 {
        fmt.Printf("Please provide input source")
        os.Exit(3)
      }
      var target string;
      if len(args) < 3 {
        target = "-"
      } else {
        target = args[2]
      }
      var source = args[1]
      command_hash(source, target)
    case "verify":
      if len(args) < 2 {
        fmt.Printf("Please provide input source")
        os.Exit(3)
      }
      if len(args) < 3 {
        fmt.Printf("Please provide a hash source")
        os.Exit(3)
      }
      var source = args[1]
      var hash = args[2]
      command_verify(source, hash)
    case "frag":
      if len(args) < 2 {
        fmt.Printf("Please provide input source")
        os.Exit(3)
      }
      var source = args[1]
      var target string;
      if len(args) < 3 {
        if source == "-" {
          target = "fragged.frag"
        } else {
          target = source + ".frag"
        }
      } else {
        target = args[2]
      }
      command_frag(source, target, DEFAULT_CHUNK_SIZE)
    default:
      fmt.Printf("Invalid command '" + args[0] + "'")
  }
}

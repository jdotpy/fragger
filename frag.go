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
import "encoding/json"
import "path/filepath"
import "crypto/sha256"

const DEFAULT_CHUNK_SIZE = 1000000
const BUFFER_SIZE int = 750000
const FILE_WRITE_PERM = 0755
const ACTIVE_FILE_NAME = "fragging.frag"

type frag_meta struct {
  Hash string
  Filename string
}

type fragged_meta struct {
  Hash string
  Fragments []frag_meta
}

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

func read_entire_file(source *os.File) string {
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
    bytes_read, err := source.Read(buffer)
    if (bytes_read > 0) {
      if (bytes_read != len(buffer)) {
        var write_slice = buffer[:bytes_read];
        hasher.Write(write_slice);
      } else {
        hasher.Write(buffer);
      }
    }
    if err == io.EOF {
      break;
    } else if err != nil {
      log.Fatal(err);
    }
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
  expected_hash := strings.TrimSpace(read_entire_file(hash_file))
  if actual_hash != expected_hash {
    fmt.Printf("Expected:\n'%v'\ngot:\n'%v'", expected_hash, actual_hash)
    os.Exit(1)
  }
}

func command_frag(source string, target string, chunk_size int) {
  target_dir := filepath.Dir(target)
  active_file_path := filepath.Join(target_dir, strconv.Itoa(rand.Int()) + ".fragging")
  source_file := get_file(source, false)
  active_file := get_file(active_file_path, true)

  meta := fragged_meta{Fragments: make([]frag_meta, 0)}
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
    if bytes_read > 0 {
      write_slice := read_slice[:bytes_read]
      chunk_bytes_left -= bytes_read
      global_hasher.Write(write_slice)
      frag_hasher.Write(write_slice)
      active_file.Write(write_slice)
    }
    if err == io.EOF || chunk_bytes_left == 0 {
      empty_chunk := chunk_bytes_left == chunk_size
      if empty_chunk {
        active_file.Close()
        _ = os.Remove(active_file_path)
      } else {
        // pull out hash and reset hasher for next fragment 
        frag_hash := hex.EncodeToString(frag_hasher.Sum(nil))
        frag_hasher.Reset();
        frag_file_name := strconv.Itoa(len(meta.Fragments)) + "-" + frag_hash[:20] + ".frag"
        frag_file_path := filepath.Join(target_dir, frag_file_name)

        meta.Fragments = append(meta.Fragments, frag_meta{Hash: frag_hash, Filename: frag_file_name})

        // Reset the active file renaming the existing one to the new fragment and truncating the active one
        active_file.Close()
        os.Rename(active_file_path, frag_file_path)
      }

      // Only re-make the "active" file if we havne't reached EOF
      if err != io.EOF {
        chunk_bytes_left = chunk_size
        active_file = get_file(active_file_path, true)
      }
    }
    if err == io.EOF {
      // If we actually hit the end of the file there are no more chunks
      break;
    }
  }
  meta.Hash = hex.EncodeToString(global_hasher.Sum(nil))

  // Create main metadata file
  metadata_json, _ := json.MarshalIndent(meta, "", "    ")
  target_file := get_file(target, true)
  target_file.Write(metadata_json)
  target_file.Close()
}

func command_defrag(source string, target string) {
  var source_dir string
  if source == "-" {
    source_dir = "."
  } else {
    source_dir = filepath.Dir(source)
  }
  meta_file := get_file(source, false)
  defer meta_file.Close()
  meta_bytes, meta_read_error := ioutil.ReadAll(meta_file)
  if meta_read_error != nil {
    fmt.Printf("Invalid fragged meta file")
    os.Exit(1)
  }
  metadata := &fragged_meta{}
  meta_parse_error := json.Unmarshal(meta_bytes, metadata)
  if meta_parse_error != nil {
    fmt.Printf("Invalid fragged meta file, cannot parse JSON metadata\n")
    log.Fatal(meta_parse_error)
    os.Exit(1)
  }

  // Now actually "cat" the files together
  target_file := get_file(target, true)
  defer target_file.Close()
  for _, fragment := range metadata.Fragments {
    frag_file := get_file(filepath.Join(source_dir, fragment.Filename), false)
    defer frag_file.Close()
    io.Copy(target_file, frag_file)
  }

  // Verify
  result_file := get_file(target, false)
  actual_hash := sha_file(result_file)
  if actual_hash != metadata.Hash {
    fmt.Printf("Expected:\n'%v'\ngot:\n'%v'", metadata.Hash, actual_hash)
    os.Exit(1)
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
          target = "stdin.fragged"
        } else {
          target = source + ".fragged"
        }
      } else {
        target = args[2]
      }
      command_frag(source, target, DEFAULT_CHUNK_SIZE)
    case "defrag":
      if len(args) < 2 {
        fmt.Printf("Please provide input source")
        os.Exit(3)
      }
      var source = args[1]
      var target string;
      if len(args) < 3 {
        target = "-"
      } else {
        target = args[2]
      }
      command_defrag(source, target)
    default:
      fmt.Printf("Invalid command '" + args[0] + "'")
  }
}

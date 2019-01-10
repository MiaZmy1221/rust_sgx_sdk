(module
  ;; (type $t0 (func (param i32 i32))) ;; type of $peek
  (type $t1 (func (param i32 i32) (result i32))) ;; type of data.externalize
  (type $t2 (func (param i32 i32 i32 i32))) ;; type of data.internalize
  (type $t3 (func (param i32) (result i32))) ;; type of data.length
  (import "data" "externalize" (func $data.ex (type $t1)))
  (import "data" "internalize" (func $data.in (type $t2)))
  (import "data" "length" (func $data.len (type $t3)))
  ;; global storing a databuf reference
  (global $ref (mut i32) (i32.const -2)) ;; index 0
  ;; one page (64 KB) of memory
  (memory (export "memory") 1)
  ;; initialize memory with a string
  ;; (data (i32.const 0) "Hi DFINITY")
  (export "init" (func $init))
  (export "set" (func $set))
  (export "peek" (func $peek))
  (func $init (param $offset i32) (param $len i32)
    (set_global $ref (call $data.ex (get_local 0) (get_local 1))))
  (func $set (param $str i32)
    (set_global $ref (get_local $str)))

  ;; the old peek function does not work for the following reason:
  ;; the initial hashmap to store the databuf and its related index is empty, 
  ;; but this function needs to get a databuf from the hashmap at the beginning and that's why it does not work
  ;; which means init() function needed to be executed firstly before this function to load a databuf into the hashmap
  ;;(func $peek (param $offset i32) (param $len i32)
  ;;  (call $data.in (i32.const 10) (call $data.len (get_global $ref)) (get_global $ref) (i32.const 0))
  ;;  (set_global $ref (call $data.ex (get_local $offset) (get_local $len))))

  ;; the new peek function
  ;; this function is intended to be executed once, since it hardcodes the data.in destination offset by 10
  (func $peek (param $offset i32) (param $len i32)
    (call $init (i32.const 0) (i32.const 10))
    (call $data.in (i32.const 10) (call $data.len (get_global $ref)) (get_global $ref) (i32.const 0))
    (set_global $ref (call $data.ex (get_local $offset) (get_local $len))))
)


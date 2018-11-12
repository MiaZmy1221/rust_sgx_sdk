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
  (data (i32.const 0) "Hi DFINITY")
  (export "init" (func $init))
  (export "set" (func $set))
  (export "peek" (func $peek))
  (func $init (param $offset i32) (param $len i32)
    (set_global $ref (call $data.ex (get_local 0) (get_local 1))))
  (func $set (param $str i32)
    (set_global $ref (get_local $str)))
  (func $peek (param $offset i32) (param $len i32)
    (call $data.in (i32.const 10) (call $data.len (get_global $ref)) (get_global $ref) (i32.const 0))
    (set_global $ref (call $data.ex (get_local $offset) (get_local $len))))
)

(assert_return (invoke "init" (i32.const 0) (i32.const 9)))

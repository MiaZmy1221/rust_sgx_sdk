(module
  (type (;0;) (func)) 
  (global $test (mut i32) (i32.const -1))
  (table (export "table") 1 anyfunc) ;; create table of size 1
  (elem (i32.const 0) $store) ;; place a pointer to the $store function in slot 0
  (func $store (type 0)
    (set_global $test (i32.const 6))
    (set_global $test (i32.const 7)))
)
;; the dif between module2 and module3 is that their function stores have different length of instructions
;; in order to test whether the implementation of comparing two funcbody objects is correct or not
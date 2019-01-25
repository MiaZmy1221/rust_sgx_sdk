(module
  (type (;0;) (func (param i32))) ;; 
  (type (;1;) (func (param i32 i32))) ;; type of func.internalize
  ;; The first two parameters is for e4's function sum, finally.
  ;; Right now, it is for e2's function callsum.
  ;; The third parameter is for e3's function inc.
  (type (;2;) (func (param i32 i32 i32)))
  (type (;3;) (func (param i32)(result i32))) ;; type of func.externalize
  (import "func" "internalize" (func $func.in (type 1)))
  (import "func" "externalize" (func $func.ex (type 3)))
  (global $g (mut i32) (i32.const 0))
  (table (export "table") 2 anyfunc)
  (memory (export "memory") 1)
  (func $store (type 0) (param i32)
    (set_global $g (get_local 0))
  )
  (func $callref (type 2) (param i32) (param i32) (param i32)
    ;; internalize $ref into slot 0
    ;; the input function is from funcmap's index 2
    ;; which is e2's function callsum
    (call $func.in (i32.const 0) (i32.const 2))
    ;; call function in slot 0
    (call_indirect (type 1) (get_local 0) (get_local 1) (i32.const 0))
    ;; internalize $ref into slot 1
    ;; the input function is from funcmap's index 3
    ;; which is e3's function inc
    (call $func.in (i32.const 1) (i32.const 3))
    ;; call function in slot 1
    (call_indirect (type 0) (get_local 2) (i32.const 1))
  )
  (export "store" (func $store))
  (export "callref" (func $callref))
)

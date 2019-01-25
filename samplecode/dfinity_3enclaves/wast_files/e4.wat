(module
  (type (;0;) (func (param i32 i32 i32)))
  (type (;1;) (func (param i32 i32))) ;; type of func.internalize
  (type (;2;) (func (param i32 i32))) ;; 
  (type (;3;) (func (param i32)(result i32))) ;; type of func.externalize
  (import "func" "internalize" (func $func.in (type 1)))
  (import "func" "externalize" (func $func.ex (type 3)))
  (global $g (mut i32) (i32.const 0))
  (table (export "table") 1 anyfunc) 
  (memory (export "memory") 1)
  (func $sum (type 2) (param i32) (param i32)
     (set_global $g (i32.add (get_local 0) (get_local 1)))
  )
  ;; Callback to e1's function callref
  (func $callback (type 0) (param i32) (param i32) (param i32)
    ;; internalize $ref into slot 0
    ;; the input function is from funcmap's index 1
    ;; which is e1's function callref
    (call $func.in (i32.const 0) (i32.const 1))
    ;; call function in slot 0
    (call_indirect (type 0) (get_local 0) (get_local 1) (get_local 2) (i32.const 0))
  )
  (export "sum" (func $sum))
  (export "callback" (func $callback))
)
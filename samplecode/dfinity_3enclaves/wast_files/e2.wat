(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func (param i32 i32))) ;; type of func.internalize
  (type (;2;) (func (param i32 i32))) ;; 
  (type (;3;) (func (param i32)(result i32))) ;; type of func.externalize
  (import "func" "internalize" (func $func.in (type 1)))
  (import "func" "externalize" (func $func.ex (type 3)))
  (global $g (mut i32) (i32.const 0))
  (table (export "table") 1 anyfunc) 
  (memory (export "memory") 1)
  (func $callsum (type 2) (param i32) (param i32)
     (set_global $g (i32.add (get_global $g) (i32.const 1)))
     ;; internalize the input function into slot 0 of the table
     ;; the input function is from funcmap's index 4
     ;; which is e4's function sum
     (call $func.in (i32.const 0) (i32.const 4))
     ;; call the function from slot 0 of the table
     (call_indirect (type 2) (get_local 0) (get_local 1) (i32.const 0))
  )
  (export "callsum" (func $callsum))
)
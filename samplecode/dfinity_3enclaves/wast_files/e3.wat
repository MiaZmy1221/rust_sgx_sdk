(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func (param i32 i32))) ;; type of func.internalize
  (type (;2;) (func (param i32))) ;; 
  (type (;3;) (func (param i32)(result i32))) ;; type of func.externalize
  (import "func" "internalize" (func $func.in (type 1)))
  (import "func" "externalize" (func $func.ex (type 3)))
  (global $g (mut i32) (i32.const 0))
  (table (export "table") 1 anyfunc) 
  (memory (export "memory") 1)
  (func $inc (type 2) (param i32)
     (set_global $g (i32.add (get_local 0) (i32.const 1)))
  )
  (export "inc" (func $inc))
)
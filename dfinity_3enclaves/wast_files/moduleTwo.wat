(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func (param i32 i32))) ;; type of func.internalize
  (type (;2;) (func (param i32 i32))) ;; type of the function that will be called
  (type $s (func)) ;; type of call_sum
  (import "func" "internalize" (func $func.in (type 1)))
  (table (export "table") 1 anyfunc) ;; create table of size 1
  (func $call_sum (type $s)
     ;; internalize the input function into slot 0 of the table
     ;; the input function is from funcmap's index2, which is sum
     (call $func.in (i32.const 0) (i32.const 2))
     ;; call the function from slot 0 of the table
     (call_indirect (type 2) (i32.const 1) (i32.const 3) (i32.const 0))
  )
  (export "call_sum" (func $call_sum))
)
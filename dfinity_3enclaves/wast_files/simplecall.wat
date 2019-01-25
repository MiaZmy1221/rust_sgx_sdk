(module
  (type (;0;) (func (param i32))) ;; type of exported function $callref
                    ;; first parameter of $callref is a funcref
  (type (;1;) (func (param i32 i32))) ;; type of func.internalize
  (type (;2;) (func)) ;; type of the function that we are internalizing
  (import "func" "internalize" (func $func.in (type 1)))
  (table (export "table") 1 anyfunc) ;; create table of size 1
  (func $callref (type 0) (param i32)
    (local i32)
    ;; internalize the input function into slot 0 of the table
    (call $func.in (i32.const 0) (get_local 0))
    ;; call the function from slot 0 of the table
    (call_indirect (type 2) (i32.const 0))
  )
  (export "callref" (func $callref))
)

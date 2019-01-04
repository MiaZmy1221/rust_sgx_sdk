(module
  (type (;0;) (func (param i32))) ;; type of exported function $callref
                    ;; first parameter of $callref is a funcref
  (type (;1;) (func (param i32 i32))) ;; type of func.internalize
  (type (;2;) (func)) ;; type of the function that we are internalizing
  (type (;3;) (func (param i32)(result i32))) ;; type of func.externalize
  (import "func" "internalize" (func $func.in (type 1)))
  (import "func" "externalize" (func $func.ex (type 3)))
  (global $g (mut i32) (i32.const 0))
  (table (export "table") 2 anyfunc) ;; table of size 2 for anyfunc
  (memory (export "memory") 1)
  (elem (i32.const 0) $store) ;; place a pointer to the $store function in slot 0
  (func $store (type 2)
    (set_global $g (i32.const 17)))
  (func $callstore (type 2)
    (local $ref i32) ;; local variable $ref stores a funcref
    ;; set $ref to the funcref obtained from externalizing slot 0
    (set_local $ref (call $func.ex (i32.const 0)))
    ;; internalize $ref back into slot 1
    (call $func.in (i32.const 1) (get_local $ref))
    ;; call function in slot 1
    (call_indirect (type 2) (i32.const 1))
  )
  (export "callstore" (func $callstore))
)

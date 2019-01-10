(module
  (type (;0;) (func (param i32))) ;; type of exported function $callref
                    ;; first parameter of $callref is a funcref
  (type (;1;) (func (param i32 i32))) ;; type of func.internalize
  (type (;2;) (func (param i32))) ;; type of the function that will be called
  (type (;3;) (func (param i32)(result i32))) ;; type of func.externalize
  (import "func" "internalize" (func $func.in (type 1)))
  (import "func" "externalize" (func $func.ex (type 3)))
  (global $g (mut i32) (i32.const 0))
  (table (export "table") 2 anyfunc) ;; table of size 2 for anyfunc
  (memory (export "memory") 1)
  (func $callstore (param $num i32)
    ;; internalize $ref into slot 0, $ref actually is the index in the hashmap: 0
    (call $func.in (i32.const 0) (i32.const 0))
    ;; call function in slot 0
    (call_indirect (type 2) (get_local $num) (i32.const 0))
  )
  (export "callstore" (func $callstore))
)

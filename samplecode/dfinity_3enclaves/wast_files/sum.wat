(module
  (type (;0;) (func (param i32)))
  (type $t (func (param i32 i32))) ;; type of sum
  (type $s (func)) ;; type of sum2
  (global $g (mut i32) (i32.const 0))
  (func $sum (type $t) (param i32 i32)
    (set_global $g (i32.add (get_local 0) (get_local 1))))
  (func $sum2 (type $s)
     (call $sum (i32.const 2) (i32.const 3)))
  (export "sum" (func $sum))
  (export "sum2" (func $sum2))
)
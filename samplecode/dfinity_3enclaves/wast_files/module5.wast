(module
  (global $test (mut i32) (i32.const -1))
  (table (export "table") 1 anyfunc) ;; create table of size 1
  (elem (i32.const 0) $store) ;; place a pointer to the $store function in slot 0
  (func $store (param $num i32)
    (set_global $test (i32.add (get_local $num) (i32.const 1))))
)

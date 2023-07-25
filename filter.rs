use seccompiler::BpfMap;
use std::convert::TryInto;

let json_input = r#"{
    "main_thread": {
        "mismatch_action": "trap",
        "match_action": "allow",
        "filter": [
            {
                "syscall": "accept4"
            },
            {
                "syscall": "fcntl",
                "args": [
                    {
                        "index": 1,
                        "type": "dword",
                        "op": "eq",
                        "val": 2,
                        "comment": "F_SETFD"
                    },
                    {
                        "index": 2,
                        "type": "dword",
                        "op": "eq",
                        "val": 1,
                        "comment": "FD_CLOEXEC"
                    }
                ]
            },
            {
                "syscall": "fcntl",
                "args": [
                    {
                        "index": 1,
                        "type": "dword",
                        "op": "eq",
                        "val": 1,
                        "comment": "F_GETFD"
                    }
                ]
            }
        ]
    }
}"#;

let filter_map: BpfMap = seccompiler::compile_from_json(
    json_input.as_bytes(),
    std::env::consts::ARCH.try_into().unwrap(),
)
.unwrap();
let filter = filter_map.get("main_thread").unwrap();

seccompiler::apply_filter(&filter).unwrap();
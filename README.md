# s4killer - BYOVD process killer

This is the source code associated with my blog post on exploiting the `probmon.sys` Minifilter driver in order to create a *process killer*.

Link <a href="https://antonioparata.blogspot.com/2024/02/exploiting-vulnerable-minifilter-driver.html">https://antonioparata.blogspot.com/2024/02/exploiting-vulnerable-minifilter-driver.html</a>

Demo video (in italian) <a href="https://www.youtube.com/watch?v=I4joF2sQWHU">https://www.youtube.com/watch?v=I4joF2sQWHU</a> where MsMpEng.exe is terminated (at 20:40)

Assigned CVE: <a href="https://www.cve.org/CVERecord?id=CVE-2024-26506">CVE-2024-26506</a>

## Build
Run `cargo build --release` in the root directory. The binary will be in `target\release\s4killer.exe`

## Usage

`s4killer.exe <PID or PROGRAM>` eg. `s4killer.exe notepad.exe`

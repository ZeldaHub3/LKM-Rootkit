# Linux LKM File-Hiding — Reverse Engineering with Ghidra

> Educational cybersecurity project focused on analyzing a Linux kernel module that hides selected files from normal directory listings.

**System:** Kali Linux
**Kernel:** Linux 6.12.33+kali-amd64
**Architecture:** x86_64
**Main tool:** Ghidra
**Technique:** ftrace-based hooking

---

## About

This project looks at how a Linux Loadable Kernel Module (LKM) can modify directory listings on a **modern Linux kernel**.

The module used in this project, `lkmdemo.ko`, filters directory entries whose names start with:

```text
malicious_file
```

The file is not deleted. Instead, the directory entry is removed from the result returned to user space, so it does not appear in a normal directory listing.

The module uses **ftrace-based hooking** to intercept the relevant directory-entry handling functions. This is particularly relevant on modern Linux kernels, where traditional kernel hooking techniques may no longer be practical or available in the same way as on older kernels.

The main purpose of the project is to understand this behavior through reverse engineering with Ghidra.


---

## Research Question

**How can Ghidra be used to identify and understand file-hiding logic inside a Linux kernel module?**

---

## Project Structure

```text
lkm-rootkit-reverse-engineering/
├── README.md
├── ftracer/
│   └── ftrace_helper.h
├── lkmdemo/
│   ├── lkmdemo.c
│   ├── Makefile
│   └── lkmdemo.ko
├── screenshots/
│   ├── ghidra-symbols.png
│   ├── suspicious-module.png
│   ├── strings.png
│   ├── function-graph.png
│   └── hook-getdents64.png
└── .gitignore
```

---

## Lab Environment

| Component           | Version / Details  |
| ------------------- | ------------------ |
| OS                  | Kali Linux         |
| Kernel              | 6.12.33+kali-amd64 |
| Architecture        | x86_64             |
| Compiler            | GCC                |
| Build               | GNU Make           |
| Reverse Engineering | Ghidra             |
| Module tools        | kmod               |

The experiment was carried out in an isolated lab environment.

---

## How It Works

The module uses ftrace to hook the directory-entry handling functions configured in the source code.

The basic flow is:

```text
Directory listing
       ↓
   ftrace hook
       ↓
Directory entries
       ↓
Filename check
       ↓
"malicious_file" match?
      / \
    yes  no
     ↓    ↓
  remove keep
   entry entry
```

For example, a directory might contain:

```text
normal_file.txt
malicious_file_test
another_file.txt
```

After the filtering logic is applied, the targeted entry is no longer shown through the normal directory-listing interface.

This does not mean that the file has been deleted from the filesystem.

---

## Building

The required packages can be installed with:

```bash
sudo apt install -y build-essential libncurses-dev linux-headers-$(uname -r)
```

Then:

```bash
cd lkmdemo
make
```

This produces:

```text
lkmdemo.ko
```

The module was built against the kernel used in the lab:

```text
6.12.33+kali-amd64
```

---

## Initial Observation

The investigation started with an unfamiliar kernel module, `lkmdemo.ko`, running in the lab environment.

Rather than assuming what the module was doing, the module and its behavior were investigated.

A temporary directory was used for the test:

```text
/tmp/test-lkm-rootkit
```

The directory was checked before and after the module was loaded:

```bash
ls -la /tmp/test-lkm-rootkit
```

The test file:

```text
malicious_file_test
```

was visible before the filtering behavior was applied and was no longer shown afterwards.

![Suspicious module / initial observation](screenshots/suspicious-module.png)
  
The behavior raised the question of how the module was able to affect the directory listing.

At this stage, the important point was not simply that a file appeared to be hidden. The system was also running an unfamiliar `.ko` module, so the next step was to investigate the module itself.

This led to the reverse-engineering phase using Ghidra.

---

## Reverse Engineering with Ghidra

The compiled `.ko` file was imported into Ghidra and analysed as an ELF object.

The analysis was used to identify the module's symbols, strings, functions, and control flow.

The investigation initially focused on finding indicators that could explain the observed behavior. In particular, attention was given to references to:

```text
getdents
ftrace
malicious_file
```

These observations provided a starting point for tracing the module's behavior through the compiled code.

The following sections show how the analysis moved from these initial indicators to the relevant parts of the module.

### Symbols

The symbol view was used to identify functions related to module initialization, cleanup, hook installation, and directory-entry processing.

![Ghidra symbols](screenshots/ghidra-symbols.png)

### Strings

The strings view was useful for finding indicators related to the filtering logic.

One of the main strings identified was:

```text
malicious_file
```

References related to `getdents` and `ftrace` also provided useful indicators for continuing the investigation.

![Ghidra strings](screenshots/strings.png)

### Function Graph

The function graph helped trace the relationship between the module initialization code, hook setup, and the filtering logic.

Following the relevant functions provided a clearer picture of how the module could intercept directory-entry processing and apply its filename filter.

![Function graph](screenshots/function-graph.png)

### Hook Analysis

The source code configures ftrace hooks for:

```text
__x64_sys_getdents
__x64_sys_getdents64
```

On older Linux systems, techniques such as directly modifying system call tables were commonly discussed for syscall hooking. On modern kernels, those approaches are generally less straightforward due to kernel hardening and changes in kernel internals.

In this project, **ftrace provides the mechanism used to intercept the relevant functions** without relying on direct syscall-table modification.

These hooks were examined during the Ghidra analysis to understand where directory-entry processing is intercepted and how the filename filtering is connected to the observed behavior.

![Hook analysis](screenshots/hook-getdents64.png)


## Main Flow

The reverse-engineering analysis connected the initial observation with the implementation inside the module:

```text
Unfamiliar .ko module
        ↓
Suspicious directory-listing behavior
        ↓
Initial investigation
        ↓
Ghidra analysis
        ↓
getdents / getdents64
        ↓
ftrace hooks
        ↓
directory entries
        ↓
filename comparison
        ↓
malicious_file*
        ↓
entry filtered
```

Following this flow in Ghidra made it possible to connect the observed behavior with the relevant functions and strings inside the compiled kernel module.

---

## Findings

| Area               | Finding                                                             |
| ------------------ | ------------------------------------------------------------------- |
| Initial behavior   | A matching file was no longer visible in a normal directory listing |
| File hiding        | Matching directory entries are removed from the returned listing    |
| Filename indicator | `malicious_file` is visible in the sample                           |
| ftrace             | Used for the configured kernel hooks                                |
| getdents           | Relevant to the directory-entry processing path                     |
| Ghidra             | Used to trace symbols, strings, and control flow                    |
| Filesystem         | Hiding a directory entry is different from deleting a file          |
| Detection          | Normal directory listings alone may not provide the full picture    |

---

## Defensive Relevance

Although this is a small lab example, the experiment shows why defenders should not rely only on normal directory listings when investigating suspicious activity.

Useful areas to investigate include:

* unexpected kernel modules
* suspicious `.ko` files
* unusual ftrace activity
* kernel logs
* file integrity
* endpoint monitoring
* differences between filesystem information sources

The indicators in this project are specific to the sample and should not be treated as universal rootkit signatures.

---

## Limitations

This was tested on:

```text
Kali Linux
Linux 6.12.33+kali-amd64
x86_64
```

The results may be different on other kernel versions or configurations.

The filename filter is also intentionally simple because the purpose of the project is to demonstrate the reverse-engineering process rather than create a general-purpose hiding mechanism.

---

## Disclaimer

This project is for educational, academic, and authorized cybersecurity research only.

The module should only be tested in systems where you have permission to do so. It is not intended for use on systems without authorization.



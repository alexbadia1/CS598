# DARPA TC Engagement 3

We provide labels for all processes that are *malicious* (label=attack) or *contaminated* by the attack (label=contaminated). 

We provide labels for all processes that are *malicious* (label=attack) or *contaminated* by the attack (label=contaminated). All other processes in the dataset are benign. The ground truth document, [available with the dataset](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md), contains additional information about each attack. We provide labels for the "Nation State" attacks, but not the "Common Threat" attacks because many of the common threat attacks are indistinguishable from normal user activity in the log files.

Each attack attempt is assigned a label according to the section number in the ground truth document. Several of the attack attempts took multiple tries to succeed, so we further divide the attack attempts into *success* and *fail* states. We do not recommend testing against the failed attack attempts because, like the common threats, they typically did not lead to a meaningful attack footprint on the target machines.

## Visualizations

To provide some intuition as to what is happening in the attacks, we provide visualizations for each. Nodes the we identified as root causes are colored red, while nodes that we identified as attack impacts are colored green. Processes that make up the attack chain are colored yellow. We have simplified the graphs for visualization purposes (deduplicated edges, merged nodes with the same label, merged multi-process programs into a single node). Thus, there are many more attack processes in the label set than appear in the visualization.

### theia_3.3_fail_allstate
![theia_3.3_fail_allstate](imgs/theia_3.3_fail_allstate.png)

### theia_3.3_fail_gatech_clean
![theia_3.3_fail_gatech_clean](imgs/theia_3.3_fail_gatech_clean.png)

### theia_3.3_success_gatech_profile
![theia_3.3_success_gatech_profile](imgs/theia_3.3_success_gatech_profile.png)

### theia_3.11_fail
![theia_3.11_fail](imgs/theia_3.11_fail.png)

### theia_3.11_success
![theia_3.11_success](imgs/theia_3.11_success.png)

## Other Notes

### Missing Data

The E3 dataset suffer from missing vertex labels to varying extents. The primary cause for this appears to be key system calls that audit frameworks missed because they weren't turned on yet. For example, if a file is `opened` before capture begins but `read` afterwards, the framework is aware that a data entity is accessed but can no longer recover the filename. The same is true for programs that were `exec`'d before capture started; the PID is referenced but the executable name is lost. If an unlabeled process appears in the attack path it is always marked as *contaminated,* not attack, as it is not possible to verify using the ground truth.

### Timing information

Note that the ground truth reports timestamps which are very useful for
correlating events in the provenance graph. These timestamps are unmarked; by
inference (since Kudu Dynamics is based in Maryland and the dataset was
collected in April) and some validation checking, we found the correct
timezone to be EDT, i.e., UTC-4.

## Why not ClearScope?
We don't include any labeling for ClearScope because the timestamps of
ClearScope seem to be in arbitrary units (e.g., like a monotonic system
clock). This makes it difficult to verify events based on their timestamps, so
we ignore ClearScope for now.

## THEIA notes
First, we focus on the Nation State attacks in E3 THEIA: one via a malicious
extension `pass_mgr`, and another via process injection directly in Firefox
processes. The report has the injection attacks in section 3.3 and the
extension attacks in section 3.11.

For each attack type, there is one successful attack and also some failed
attempts. For completeness, we created subgraphs for all observed attacker
behaviors, even the failed ones.

Note that THEIA clearly had some lost logs during capture, as indicated by
both the ground truth report and the operational log. This directly manifests
in the observed subgraphs, which are missing some key logs. For example, some
of the initial attack steps such as malicious ad servers reported in the
ground truth report don't seem to appear in the logs themselves. In these
cases, we tried our best to include what initial attack steps we could, but a
couple of events may be missing here. Essentially all of our attack traces
started from the reported shellcode server IP addresses, as the malicious ad
servers generally don't appear in the logs.

Another example: both successful attacks involve an extra malicious process
(`/home/admin/profile` and `/var/log/mail`) that should be forked somewhere
based on UNIX process semantics. However, in the logs, these processes "appear
out of nowhere", i.e., they are the roots of their own process trees, and are
furthermore executed from files with missing data (specifically, we don't know
the file paths). Unless an automated method somehow anticipates these details
without overapproximating other portions of the attack, this simply
demonstrates why manual inspection is necessary to correctly reconstruct the
attack.

Although we've discussed the attacks as though they are separate, in reality
operational errors made the attackers decide to use the first attack
(specifically, the malicious `/home/admin/profile` process) to bootstrap the
second attack's `/var/log/mail` process. Rather than replicate all of the
`profile` attack in the `mail` attack, we simply start from the `profile`
process and don't label anything preceeding that.

### 4.8: THEIA tcexec
We found `tcexec` in the logs, although as the ground truth indicates, the
attack failed and `tcexec` didn't really do anything interesting. Furthermore,
it was manually downloaded and executed, so it's debatable whether it should
even be considered attacker behavior. We reproduced the tiny subgraph anyways
just in case it is ever needed.

## TRACE notes
We focus on the 3 Nation State TRACE attacks. Note that unlike THEIA, TRACE
had execution partitioning using BEEP. This specifically shows up in the
attack logs, as firefox was execution-partitioned and so many of its behaviors
are attributed to execution units, not to an overall firefox process.

An important note for the TRACE provenance graph: TRACE's usage of CDM events
seems to differ the most from other datasets: there are instances of `exec`
events between two processes (as opposed to a process and file), which doesn't
actually make sense based on the UNIX `exec` semantics; these should be clones
instead (or perhaps they represent versioning, which does make sense, but in
that case there should also be some reference to the executed program binary).
Additionally, there are `loadlibrary` events that seem to fit the role of UNIX
`exec` calls; e.g., a `wget` process has a `loadlibrary` call referencing the
`wget` binary. We have verified that TRACE is the only dataset of the four
surveyed here that uses `exec` in this way.

### 3.2: Firefox Backdoor
Like THEIA, TRACE attacks also had many failed attempts. Rather than creating
a separate subgraph for each failed attempt, we collected them all into one.
The report mentions that errors caused TRACE to lock up, which resulted in
lost logs and a massive spike in activity. From the provenance graph, we once
again don't see any evidence of the malicious server (`145.199.103.57:80`),
but we do see the shellcode server. Therefore, many of the reported
connections from 10:22 to 10:40 are not visible.

Additionally, the massive spike in activity for the failed attacks is evident.
The first attack just appears as a single isolated process with a massive
flurry (~9 million events) of network I/O activity that is probably related to
the observed server unresponsiveness. The second failure is much smaller and
also has a single firefox process with no other activity.

The logs reference `/home/admin/cache`, which does appear in the logs,
`/dev/glx_alsa_675`, which does appear in the logs, and `/var/log/xtmp`, which
does not. We were able to find a parent of `cache` with some unknown name, but
hit a dead end from that point (and the parent appears to have UNIX timestamp
0). Similarly, we were able to find when the firefox event unit writes to
`/dev/glx_alsa_675`, but couldn't find an apparent link to `cache`. Therefore,
these two portions of the attack subgraph appear disconnected, though there is
logically some edge (either not handled by our provenance graph or not
captured correctly) that should connect these attack steps together.

### 3.12: Firefox Extension
The ground truth indicates this attack failed. The two referenced addresses
are not in the logs. However, the shellcode server seen in 3.2 does actually
appear at the referenced time (04/12 13:36), and from it, we do see the
malicious `pass_mgr` extension. Once again, we see evidence of the mass events
that are related to the server being unresponsive (~240 million events!)

### 3.15: "Pine Backdoor"
Not exactly sure why this is called pine backdoor, as it actually traces to
the Firefox browser extension --- the ground truth doesn't even mention pine
until the provenance graph. In fact, the pine attack involving tcexec seems to
be a different attack entirely (one of the common threat phishing attacks).

From examining the logs, this attack is actually started by `pass_mgr` at
04/13 12:43, which creates `gtcache` via `sh`. `gtcache` then creates `ztmp`
in the same manner. (We initially believed these processes were all detached,
but realized that they are connected by `exec` events between two processes,
instead of the `clone` events we expected to see.)

### 4.9: TRACE tcexec
This is where the pine backdoor graph was supposed to be. This attack is
somewhat complicated by the brute force attempts to make failed steps
succeed. For example, one of the `tcexec` processes was simply run via an
interactive terminal (it can be traced through `bash` to `xfce4-terminal`,
indicating this was intentionally run). We include this `tcexec` process (but
not its parent `bash` session), although it is less clear whether this is
technically an attacker behavior or not.

The second attempt of using `tcexec` manages to execute its port scanning
behavior. This one was launched by `pine` as indicated by the ground truth. We
record this as the `successful` attack, although it was only able to perform
port scanning and not launch a shell.

## CADETS notes
CADETS is a FreeBSD host and appears to have worse log capture than the Linux
and Windows hosts. For example, many key processes such as `nginx` are
actually missing process name information, although we can infer that they are
`nginx` based on their behavior (e.g., writing to an `nginx` access log). For
some processes we can also infer the name from `exec` events, although this is
not always possible.

### 3.1: nginx Backdoor
The ground truth indicates CADETS crashed during this attack. It refers to a
file `/var/log/devc` that doesn't appear anywhere in the logs --- the logs
were probably lost due to the crash. We are able to see evidence of `nginx`
communicating with the shellcode server and the other malicious processes,
`/tmp/vUgefal`. Since `nginx` is a long-running process, we need to be careful
when constructing the attack subgraph not to include all of its edges.

The provenance for `vUgefal` is actually unclear: it is forked by a process
with a missing timestamp that exhibits a lot of different behaviors, and it is
long-running. Since we were unable to figure this out, we settle for just
including `vUgefal` and the attack portions of `nginx` in the subgraph.

### 3.8: nginx Backdoor 2
Based on the ground truth, this is essentially just repeating Section 3.1,
even with the same result of crashing CADETS at the end. This time, we don't
see any evidence of the reported malware (`/tmp/grain`), so we can only
reconstruct the communication with nginx.

### 3.13: nginx Backdoor 3
Once again, this is like Section 3.1. We still have malware processes that
seem disconnected from `nginx` although there are many more. Notably, the
final `test` process seems to have a lot more activity than previous attacks.

### 3.14: nginx Backdoor 4
Same deal as before - once again, many of the referenced files (e.g.,
`eWq10bVcx`, `memhelp.so`, `eraseme`, and `done.so` don't appear in the logs).

## FiveDirections notes
FiveDirections is the Windows host, but fortunately the CDM means the logs are
formatted in the same way. The ground truth references FiveDirections in one
of the TA5.2 sections (Section 3.5), but this seems to have been a
documentation error.

### 3.4: Firefox Backdoor
The firefox process that becomes compromised is relatively short-lived, so we
add the entire subgraph after the first connection to the shellcode server.
Note that some of the referenced files (e.g., "locomotives.rtf",
"Covert.xlsx") don't seem to appear in the logs.

Note that the shellcode server in the ground truth (`156.78.147.114:80`)
actually appears unreported again at around 04/11 11:57 and 04/12 10:08. Not
sure if this is a logging error or not --- we chose to ignore this.

### 3.10: Firefox Extension
As usual, the webserver doesn't appear in the logs, so we use the shellcode
server instead. Once again, this report doesn't seem to fully line up with the
logs: there are actually 2 connections to the shellcode server, and the second
one did successfully download the malware `hJauWl01` as reported. However,
though this wasn't reported, the malware was actually successfully able to
run, though it didn't do anything. We have a separate subgraph for the malware
running in case it is useful.

### 4.4: Malicious Excel Script
As the ground truth indicates, the excel macro failed to run successfully, but
the malicious PowerShell script was then run manually instead. They also note
that they were able to run a command shell and access a bunch of files. We
found the shell (`cmd.exe`, not `powershell.exe`), but not the link between
the `cmd` session and the `powershell` script. We isolated both as separate
subgraphs.

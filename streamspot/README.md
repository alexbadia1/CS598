# StreamSpot Event Labels
`streamspot_labels.csv` contains our process labeling for the raw SystemTap (stap) logs of
the StreamSpot dataset.
Each line corresponds to malicious attack process;
  `file_no` indicates the attack log file (0-99),
  `process_name` is the process name,
  `pid` is the process id and `tid` is the thread id (`pid=tid` for single-threaded processes).

Some additional notes on these labels:

* Ground truth documentation is not available for this dataset, and when we approached
  the authors about the attack in 2019 they could not remember specific details. However,
  given the small size of each log file the attack is pretty easy to identify. The chain
  is comprised of the adversary compromising firefox and then issuing several shell commands
  afterwards.

* We use the socket address `192.168.0.100` as the root cause and the shell command
  `ps x` as the impact node for the attack. The former is the address of the attacker,
  whereas the latter is needed to ensure all the attacker shell activity is
  correctly labeled.

# StreamSpot Event Labels
`attack_events.xz` contains our labeling for the raw SystemTap (stap) logs of
the StreamSpot attack dataset. The labels are formatted as a list of
newline-separated `{trial}-{line}` strings, where `{trial}` is the number of
the attack trial (in the range 0 to 99), and `{line}` is the 0-indexed line
number of the audit event within that file — i.e., the header is line 0, the
first audit event is line 1, etc.

Some additional notes on these labels:

* We use the socket address `192.168.0.100` and any process executing `ps x`
  as starting nodes for the attack. The former is the address of the attacker,
  whereas the latter is needed to ensure all the attacker shell activity is
  correctly labeled.

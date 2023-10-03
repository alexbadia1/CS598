# REAPr: Recovery Every Attack Process 

## Standardizing Ground Truth IDS Labels

As intrusion detection systems have become more advanced, the potential for *researcher intent*
  to influence evaluation results has become a greater concern.
Many of today's popular intrusion detection datasets are inconsistent in how they provide
  ground truth as to the attacks contained therein -- some provide label specific entities
  and events as malicious, others may specify that the attack is contained in a specific log file,
  while others may only release a qualitative description of the attack.
Because of this inconsistency, individual experimenters are left to make their own decisions as to
  which events/entities should be designated as malicious.
The researcher is strongly motivated for the system under test to perform well in experiments,
  creating the potential for biased decision making in ad hoc ground truth labeling.

This repository contains standardized ground truth labeling for a intrusion detection datasets 
  used in the security literature.
We propose a generic and universally applicable labeling methodology for endpoint events --
  *the ideal intrusion detection system should identify every attacker-controlled and -influenced process.*
To facilitate this, we perform semi-automated labeling of popular datasets using provenance 
  analysis techniques that have been appeared in the security literature.
We also provide detailed documentation of our work, 
  including visualizations of each and every attack,
  so that researchers can understand and independently verify our work, should they choose.
It is our hope that these efforts will improve the rigor and uniformity of experimental
  results in threat detection research.

## Dataset Labeling Methodology

Here, we describe the general process used to create these
labels here; for more specific details, see the READMEs accompanying each
dataset's labels.

We labeled datasets according to the following basic outline:

1. Use prior knowledge to determine key attack events. Most datasets have some
   accompanying ground truth document describing how the attacks were
   conducted. We are specifically looking for the starting point of each
   attack, but also track any other documented attack events to ensure they
   end up correctly being labeled as attack.
2. Using a provenance graph, identify the node(s) associated with each of
   the key attack events. For each node, determine whether it is a root cause node
   (beginning of the attack), impact node (end of the attack), or intermediary node.   
   Locating specific nodes is aided by knowing the process name, time of the attack
   event, and names of nearby nodes (e.g., socket addresses).
3. Perform a process-only forward trace from root cause node(s): traverse all graph
   nodes that are immediate descendents of (i.e., information flowed from)
   this root cause node. Recursively repeat this process only for
   __process nodes__. The goal of this is to avoid label explosion, but not
   propagating through files could possibly disconnect parts of the graph
   If multiple root cause nodes, take the union of the sets of nodes
   identified by each forward trace.
4. Perform a process-only backward trace from impact node(s): traverse all graph
   nodes that are immediate ancestors of (i.e., information flowed to)
   this impact node. Recursively repeat this process only for
   __process nodes__. If multiple impact nodes,
   take the union of the sets of nodes identified by each back trace.
5. Label the set of all nodes in the forward trace from the root causes as
   CONTAMINATED. Then, update the labels for the intersection of the forward
   and backward traces as MALICIOUS. Label all other nodes as BENIGN.
6. Verify that all key attack nodes identified in step 1 are now
   labeled as MALICIOUS. If not, manually backtrace through the graph from these
   attack entities until reaching a MALICIOUS node, then perform a forward
   trace from these branches of the attack. Assign nodes in the intersection
   of the forward and backwards traces the MALICIOUS label.
   If connecting the sections of the graph is not possible, this is likely due
   to missing data in the log file and the attack is left disconnected.
   This second pass over the attack graph helps to ensure that we have a
   complete (as possible) attack graph without overlabeling in the first pass.
7. Visualizes the results of our labeled attack graph to determine if it 
   reflects our expectations based on prior knowledge of the attack
   (e.g., from external ground truth documentation). 
8. Output the label for all process nodes in the final label file.
   If finer-grained tasks such as thread or execution unit IDs are available
   in the original log file, use these instead of process id.
   We choose to evaluate on process entities only, as opposed to file or socket
   entities, etc., as only process entities are agentive. This is also more
   consistent with commercial endpoint detection products. 

## Publishing using the REAPr Ground Truth Labels

We encourage you to use these attack labels in your experiments. 
If you do so, please specify that you are using these labels by name (REAPr) in your experimental setup section
  and cite the BibTeX entry below.
Please also mention in the experimental setup section the month and year of the commit you are working off of
  just in case we identify an error and need to update the existing label sets.

```
@misc{reapr-ground-truth,
  author = {Jason Liu and Adil Inam and Akul Goyal and Kim Westfall and Andy Riddle and Adam Bates},
  title = {REAPr: Recovery Every Attack Process},
  year = {2023},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://bitbucket.org/sts-lab/reapr-ground-truth}},
  commit = {ENTER COMMIT DIGEST HERE}
}
```

## Contributing to REAPr

If you have generated a threat detection dataset comprised (at least in part) of endpoint logs,
  we would be happy to feature your labels in this repository.
We ask that you follow our labeling methodology and then provide us with:
  human-readable graph visualization(s) of the attack behaviors;
  a CSV containing labels for all processes in the dataset, 
  making sure that each process can be uniquely identified in the logs using the information in the CSV;
  and instructions for how to access the dataset.
Feel free to reach out if you need guidance on any of these points.
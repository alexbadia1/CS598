# Dataset Labeling Process
This repository contains attack labels we have manually created for various
system audit datasets. We describe the general process used to create these
labels here; for more specific details, see the READMEs accompanying each
dataset's labels.

We labeled datasets according to the following basic outline:

1. Use prior knowledge to determine key attack events. Most datasets have some
   accompanying ground truth document describing how the attacks were
   conducted. We are specifically looking for the starting point of each
   attack, but also track any other documented attack events to ensure they
   end up correctly being labeled as attack.
2. Using a provenance graph, identify the starting node(s) of the attack as
   the process associated with the initial attack behavior. Locating this
   specific node is aided by knowing the process name, time of the attack
   event, and names of nearby nodes (e.g., socket addresses).
3. Perform a process-only forward trace from starting node: traverse all graph
   nodes implicated by this starting node, and label all the traversed nodes
   and events as attack. Then, recursively repeat this process only for
   __process nodes__. The goal is to avoid label explosion, but not
   propagating through files could possibly disconnect parts of the graph.
4. Double-check that all the attack entities identified in step 1 are now
   labeled as attack. If not, manually backtrace through the graph from these
   attack entities until reaching an attack node, and perform the forwards
   process trace from these branches of the attack. **In the worst case, we
   were occasionally unable to fully connect all pieces of the attack.**
   Because we primarily intend to use these labels for IDS evaluation, this
   should hopefully have a fairly minimal effect on the results as only a
   small fraction of attack events will be mislabeled.
5. We attempt to verify the results of our labeling by viewing the resulting
   subgraphs and comparing if they reflect our expectations based on prior
   knowledge of the attack (e.g., from external ground truth documentation).
   This step can be difficult due to the large size of provenance subgraphs.
6. We collect all the labeled attack nodes, and reparse the raw event stream
   used to construct the provenance graph, additionally labeling any event
   related to an attack process **that occurs after the process is
   compromised** as malicious. This step is necessary because not all events
   are relevant to provenance graphs, but certain tasks may require labeling
   for all audit events. We deem **any event being performed by a compromised
   process as being malicious** — note that this may potentially include
   ongoing or mimicked benign behaviors.

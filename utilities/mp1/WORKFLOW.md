### Quickstart

> root_cause_ip=110.195.179.70:22

Adam Bate found this in class...

Something to do with the domain network controller (dnc) being part of the attack?

#### IF THE DUMPED VERTICES (mp1/h3_attack.csv) EXIST:

```shell
# 0. Main working directory
cd utilities

# 1. Manually update attack labels (root_cause, impact, benign) in mp1/h3_attack.csv

# 2. Run the trace thingy
python igraph-to-viz.py mp1/h3_attack.pickle.xz
```

#### ELSE IF STARTING FRESH:

```shell
# 0. Main working directory
cd utilities

# [Optional] Dump edges
python dump_edges.py mp1/h3_attack.pickle.xz > mp1/h3_attack_edges

# 1. Dump vertices (this will RESET attack labels)
python dump_vertices.py mp1/h3_attack.pickle.xz > mp1/h3_attack.csv

# 2. [Skip because not yet implemented] Pollinate
# python pollinate.py mp1/h3_attack.pickle.xz

# 3. Visualize
python igraph-to-viz.py mp1/h3_attack.pickle.xz


# Filtering the graph to a certain time window breaks things:
#
# python filter.py mp1/h3_attack.pickle.xz
# python dump_vertices.py mp1/h3_attack_filtered.pickle.xz > mp1/h3_attack_filtered.csv
# python igraph-to-viz.py mp1/h3_attack_filtered.pickle.xz
```

### Adam Bate's Lab Demo Logs September 26, 2024

Here's the logs from Adam Bate's lab demo September 26, 2024:

>[docs/console1.rtf](docs/console1.rtf) \
>[docs/console2.rtf](docs/console2.rtf)

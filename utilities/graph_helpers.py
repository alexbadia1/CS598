import csv
import igraph
import matplotlib.pyplot as plt
import os
import sys
import pickle
import pdb
import lzma

def forward_trace(g, vertex_id, timestamp, visited):

    ancestor = g.vs[vertex_id]
    descendents = []

    if vertex_id in visited:
        return descendents
    else:
        visited.append(vertex_id)
    
    for e in g.es.select(_source = ancestor):
        if e.target in visited:
            continue
        else:
            if int(e["time"]) >= timestamp:
                descendents.append(e.target)
                descendents = descendents + forward_trace(g, e.target, int(e["time"]), visited)
    return descendents

def backward_trace(g, vertex_id, timestamp, visited):

    descendent = g.vs[vertex_id]
    ancestors = []

    if vertex_id in visited:
        return ancestors
    else:
        visited.append(vertex_id)
    
    for e in g.es.select(_target = descendent):
        if e.target in visited:
            continue
        else:
            if int(g.vs[e.target]["time"]) <= timestamp:
                ancestors.append(e.target)
                ancestors = ancestors + forward_trace(g, e.source, int(e["time"]), visited)
    return ancestors

def print_node(g, vertex_id):
    v = g.vs[vertex_id]
    print("[v%d](%s)" % (v.index, v["name"]))

def print_edge(g, edge_id):

    e = g.es[edge_id]
    s = g.vs[e.source]
    t = g.vs[e.target]
    
    print("[v%d](%s) --[e%d](%s){%d}--> [v%d](%s)" % (
        s.index, s["name"], e.index, e["type"],int(e["time"]),
        t.index, t["name"]))
    
def pickle_read(path):

    if path.endswith("xz"):
        opener = lzma.open
    else:
        opener = open
    with opener(path, "rb") as f:
        return pickle.load(f)

def pickle_write(data, path):
    if path.endswith("xz"):
        opener = lzma.open
    else:
        opener = open
    with opener(path, "wb") as f:
        pickle.dump(data, f, protocol=config.pickle_protocol)
    

# Any dataset-specific relabels go here
def relabels(g):

    winfile_prefix_filters = ["c:\\users\\aalsahee\\appdata\\local\\microsoft\\windows",
                              "c:\\users\\aalsahee\\appdata\\local\\",
                              "c:\\users\\aalsahee\\appdata\\roaming\\microsoft\\windows",                   
                              "C:\\Users\\admin\\AppData\\Local",
                              "C:\\Users\\admin\\AppData\\Roaming",
                              "C:\\Users\\admin\\AppData",
                              "C:\\Users\\admin\\Documents",
                              "C:\\Users\\admin",
                              "C:\\Users",
                              "C:\\Windows",
                              "C:\\Program Files",
                              "C:\\"]
    
    winfile_suffix_filters = ["\\a6gl280b.default\\",
                              "\\lrjbrdp5.default\\",
                              "\\mozilla firefox\\"
                              "\\customdestinations\\",
                              "\\temporary internet files\\",
                              "\\\wdi\\",
                              "System32\\en-US",
                              "System32"]


    
    for i in range(0,len(g.vs)):
        if " (deleted)" in g.vs[i]["name"]:
            g.vs[i]["name"] = g.vs[i]["name"].replace(" (deleted)","")

        if g.vs[i]["name"].startswith("sock="):
            g.vs[i]["name"] = g.vs[i]["name"].split("=")[1]

        if '\x00' in g.vs[i]["name"]: 
            #name = g.vs[i]["name"].lstrip('\x00')
            g.vs[i].update_attributes({"name":""})

        # Split unix file paths, keep file name        
        if '/' in g.vs[i]["name"]:
            name = g.vs[i]["name"].split('/')
            name = name[len(name)-1]
            g.vs[i].update_attributes({"name":name})

        # Gave up on cleaning up regkeys, just rename to "regkey"
        if g.vs[i]["type"] in ["regkey"]:
            g.vs[i].update_attributes({"name":"regkeys"})
                    
        # Split windows file paths, keep file name
        if '\\' in g.vs[i]["name"]:
            modified = False
            name = g.vs[i]["name"]
            for prefix in winfile_prefix_filters:
                if prefix in name:
                    name = name.split(prefix)
                    name = name[len(name)-1]
                    
            for suffix in winfile_suffix_filters:
                if suffix in name:                
                    name = name[:name.index(suffix) + len(suffix)]
            
            if not modified and False:
                name = name.split('\\')
                name = name[len(name)-1]
            g.vs[i].update_attributes({"name":name})
            
    for i in range(0, len(g.es)):
        if g.es[i]["type"].startswith("EVENT_"):
            g.es[i]["type"] = g.es[i]["type"].split("_")[1]
            g.es[i]["type"] = g.es[i]["type"].lower()

# Modify processes to denote UUIDs
#  (must be done later in processing than relabels())            
def mark_uuids(g):
    for i in range(0,len(g.vs)):
        if g.vs[i]["type"] == "process":
            g.vs[i]["name"] = g.vs[i]["name"]+":"+str(g.vs[i]["uuid"])[:4]
            
# Color the graph
def color_graph(g, seed_file):

    seed_labels={}
    if os.path.isfile(seed_file):
        try:
            with open(seed_file,'r') as csvfile:
                rdr = csv.reader(csvfile)
                for row in rdr:
                    seed_labels[row[3]] = row[4]
        except Exception as e:
            print("Error: %s" % (e))
            pdb.set_trace()
            
        g.vs["color"] = g.vs["type"]
        color_dict = {"root_cause": "red", "impact": "green",
                      "contaminated": "grey", "benign" : "grey",
                      "descendent": "yellow", "attack": "yellow"}
        root_vertex_ids = []
        impact_vertex_ids = []
        for i in range(0,len(g.vs["color"])):
            v_uuid = str(g.vs[i]["uuid"])
            try:
                g.vs[i]["color"] = color_dict[seed_labels[v_uuid]]
            except Exception as e:
                print("Error: %s" % (e))
                pdb.set_trace()
                
            if seed_labels[v_uuid] == "root_cause":
                root_vertex_ids.append(g.vs[i].index)
            elif seed_labels[v_uuid] == "impact":
                impact_vertex_ids.append(g.vs[i].index)

        # Propagate root cause taint in graph colors
        descendents = []
        for r in root_vertex_ids:
            descendents = descendents + forward_trace(g, r, int(g.vs[r]["time"]),  [])
        ancestors = []
        for i in impact_vertex_ids:
            ancestors = ancestors + backward_trace(g, i, int(g.vs[i]["time"]), [])

        attack_chain = [vertex for vertex in descendents if vertex in ancestors]
        attack_chain = descendents
        for d in attack_chain:
            if seed_labels[g.vs[d]["uuid"]] in ["root_cause", "impact"]:
                continue
            elif g.vs[d]["type"] != "unknown":
                g.vs[d]["color"] = color_dict["descendent"]
    else:
        color_dict = {"process": "blue", "file": "green", "regkey": "green", "socket": "yellow", "unknown": "grey", "alert": "red"}
        g.vs["color"] = [color_dict[t] for t in g.vs["type"]]
        
# Declone processes
def declone_processes(g):

    parent_mapping = {}
    prune_set_e = []
    prune_set_v = []
    for ei in range(0,len(g.es)):
        e1 = g.es[ei]

        if(e1["type"] == "clone" and
           g.vs[e1.source]["name"] == g.vs[e1.target]["name"]):

            if e1.target in parent_mapping:
                parent_mapping[e1.target] = parent_mapping[e1.source]
            else:
                parent_mapping[e1.target] = e1.source
            
        
            #        print("Declone (E%d): Delete Vertex %d[%s] and connect its edges to Vertex %d[%s]" %
            #              (e1.index, e1.target, g.vs[e1.target]["name"],
            #               parent_mapping[e1.target], g.vs[parent_mapping[e1.target]]["name"]))
                
            node_to_prune = g.vs[e1.target]
            node_to_rehome = g.vs[parent_mapping[e1.target]]
            prune_set_v.append(e1.target)
            prune_set_e.append(e1.index)
            
            for e in g.es.select(_source = node_to_prune):
                if e.index == e1.index:
                    continue

                new_e = g.add_edge(node_to_rehome.index, e.target)
                new_e["type"] = e["type"]
                new_e["time"] = e["time"]
                new_e["uuid"] = e["uuid"]            
                prune_set_e.append(e.index)
                #            print("\t Update source vertex for E%d: <src:%d, tgt:%d, type:%s> to %d" %
                #                  (e.index, e.source, e.target, e["type"], node_to_rehome.index))

            for e in g.es.select(_target = node_to_prune):
                if e.index == e1.index:
                    continue

                new_e = g.add_edge(e.source, node_to_rehome.index)
                new_e["type"] = e["type"]
                new_e["time"] = e["time"]
                new_e["uuid"] = e["uuid"]            
                prune_set_e.append(e.index)
                #           print("\t Update target vertex for E%d: <src:%d, tgt:%d, type:%s> to %d" %
                #                 (e.index, e.source, e.target, e["type"], node_to_rehome.index))
                
    g.delete_edges(prune_set_e)
    g.delete_vertices(prune_set_v)

# Remove redundant edges and vertices from graph
def prune_edges(g, debug=False):
    prune_set_e = []
    for e1 in g.es:

        # Skip if edge is already marked for pruning
        if e1.index in prune_set_e:
            continue
        
        for e2 in g.es.select(_source=e1.source, _target=e1.target):
            # Skip if e1 is e2
            if e1.index == e2.index:
                continue
            # Skip if edge is already marked for pruning
            elif e2.index in prune_set_e:
                continue
            # Skip if edges are not of the same type
            elif e1["type"] != e2["type"]:
                continue
            # Prune edge since target and source indices match            
            else:
                prune_set_e.append(e2.index)

    g.delete_edges(prune_set_e)

def _all_neighbors(g, vi):

    neighbors = []
    for e in g.es.select(_source = vi):
        v = g.vs[e.target]
        neighbors.append(v.index)

    for e in g.es.select(_target = vi):
        v = g.vs[e.source]
        if v.index not in neighbors:
            neighbors.append(v.index)

    return neighbors

    
# Remove dangling vertices (applied after prune vertices)
def _prune_vertices(g, debug=False):

    prune_set_v = []
    for vi in range(0, len(g.vs)):
        v = g.vs[vi]
        if(len(g.es.select(_source = v.index)) == 0
           and len(g.es.select(_target = v.index)) == 0):
            prune_set_v.append(v.index)
    g.delete_vertices(prune_set_v)

# For each known vertex,
#   if two of its neighbors are semantically equivalent
#   (same file or socket name, or type is unknown)
#   and do not convey any additional information flow,
#   drop the edge to one of the two neighbors.
# At the end, remove any disconnected vertices
def merge_vertices(g, debug=False):

    prune_set_e = []
    prune_set_v = []
    # Iterate over all nodes
    for v in g.vs:
        # Skip if v is already marked for deletion
        if v.index in prune_set_v:
            continue
        # Skip if this isn't a process (we'll visit every node either way)
        elif v["type"] != "process":
            continue
            
        neighbors = _all_neighbors(g, v.index)
        for n1 in range(0,len(neighbors)-1):
            v1 = g.vs[neighbors[n1]]

            # Skip if first neighbor is already marked for deletion
            if v1.index in prune_set_v:
                continue
            
            for n2 in range(n1+1, len(neighbors)-1):
                v2 = g.vs[neighbors[n2]]

                # Skip if second neighbor is already marked for deletion
                if v2.index in prune_set_v:
                    continue
                
                # Merge candidate if both are unknown
                # Merge candidate if both have same data entity name
                if( (v1["type"] == "unknown" and v2["type"] == "unknown")
                    or (v1["type"] in ["file", "socket", "regkey"]
                        and v2["type"] in ["file", "socket", "regkey"]
                        and v1["name"] == v2["name"])
                    or (v1["name"] == "" and v2["name"] == "")):
                    
                    node_to_keep = v1
                    node_to_prune = v2
                    prune_set_v.append(v2.index)
                    
                    for e in g.es.select(_source = node_to_prune):                        
                        if e.index == node_to_keep.index:                        
                            continue

                        new_e = g.add_edge(node_to_keep.index, e.target)
                        new_e.update_attributes(e.attributes())
                        prune_set_e.append(e.index)

                    for e in g.es.select(_target = node_to_prune):
                        if e.index == node_to_keep.index:
                            continue

                        new_e = g.add_edge(e.source, node_to_keep.index)
                        new_e.update_attributes(e.attributes())
                        prune_set_e.append(e.index)


    g.delete_edges(prune_set_e)    
    g.delete_vertices(prune_set_v)

def lamport_timestamps(g):

    timestamps = []
    for e in g.es:
        timestamps.append(e["time"])
    for v in g.vs:
        timestamps.append(v["time"])

    timestamps.sort()
        
    for e in g.es:
        e["time"] = timestamps.index(e["time"])

    for v in g.vs:
        v["time"] = timestamps.index(v["time"])
    
    

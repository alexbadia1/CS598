import csv
import igraph
import matplotlib.pyplot as plt
import os
import sys
import pickle
import pdb
import lzma
import traceback

# Why do I need this??? >_<
FUZZY_TRACE_TIME = 100

color_dict = {
    "root_cause": "#5AFA8E", # green
    "impact": "#FA5D5A", # red
    "process": "#5A62FA", # blue
    "file": "#FADB59", # yellow
    "regkey": "#FADB59",
    "socket": "#FADB59",
    "descendent": "#FADB59",
    "attack": "#FADB59",
    "contaminated": "grey", "benign" : "grey", "default": "grey",
} 


def forward_trace(g, vertex_id, depth, timestamp, visited, max_time = False, impacts_only = False):
    
    ancestor = g.vs[vertex_id]
    descendents = []

    #### FORWARD TRACE ONLY####
    # Specify Sugiyama layer
    g.vs[vertex_id]["layer"] = depth
    
    if vertex_id in visited:
        return descendents
    else:
        visited.append(vertex_id)
        
    terminal_node = True
    for e in g.es.select(_source = ancestor):
        if e.target in visited:
            continue
        else:
            if (
                    (not timestamp or timestamp <= (e["etime"] + FUZZY_TRACE_TIME))
                    and (not max_time  or max_time  >= (e["time"] - FUZZY_TRACE_TIME))
            ):
                terminal_node = False
                #print_edge(g,e.index,"\t" * depth)
                g.es[e.index]["attack_label"] = True
                descendents = descendents + forward_trace(g, e.target, depth + 1,
                                                          int(e["time"]), visited, max_time, impacts_only)

    if not impacts_only or (impacts_only and terminal_node):
        descendents.append(vertex_id)

    return descendents

def backward_trace(g, vertex_id, depth, timestamp, visited, min_time = False, root_causes_only = False):

    descendent = g.vs[vertex_id]
    ancestors = []

    if vertex_id in visited:
        return ancestors
    else:
        visited.append(vertex_id)

    terminal_node = True
    for e in g.es.select(_target = descendent):
        if e.source in visited:
            continue
        else:
            if (
                    (not timestamp or timestamp >= (e["time"] - FUZZY_TRACE_TIME))
                    and (not min_time  or min_time  <= (e["etime"] + FUZZY_TRACE_TIME))
            ):
                terminal_node = False
                #print_edge(g,e.index,"\t" * depth)
                g.es[e.index]["attack_label"] = True
                ancestors = ancestors + backward_trace(g, e.source, depth + 1,int(e["time"]), visited, min_time, root_causes_only)

    if not root_causes_only or (root_causes_only and terminal_node):
        ancestors.append(vertex_id)
    
    return ancestors

def print_node(g, vertex_id, prefix=""):
    v = g.vs[vertex_id]
    print("%s[v%d](%s, %s)" % (prefix, v.index, v["name"], str(v["uuid"])))

def print_edge(g, edge_id, prefix):

    e = g.es[edge_id]
    s = g.vs[e.source]
    t = g.vs[e.target]
    
    print("%s[v%d](%s) --[e%d](%s){%d}--> [v%d](%s)" % (prefix,
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

    # Drop leading substrings that match these
    winfile_prefix_filters = []

    # Drop ending substrings that come after these matches
    winfile_suffix_filters = []


    
    for i in range(0,len(g.vs)):
        name = g.vs[i]["name"]
        node_type = g.vs[i]["type"]

        #######################################
        #      DARPA E3 Hacks
        #######################################
        # Remove "deleted" from red team executable names
        if " (deleted)" in name:
            g.vs[i]["name"] = name.replace(" (deleted)","")

        # Remove sock= prefix from sockets
        if name.startswith("sock="):
            g.vs[i]["name"] = name.split("=")[1]

        # Remove null prefix from unknown node labels,
        #  replace with empty string
        if '\x00' in name: 
            g.vs[i].update_attributes({"name":""})

        #######################################
        #      Unixy Hacks
        #######################################            
        # Split unix file paths, keep file name
        if node_type == "file" and '/' in name:
            name = name.split('/')
            name = name[len(name)-1]
            g.vs[i]["name"] = name
            
        #######################################
        #      Windowsy Hacks
        #######################################
        # Gave up on cleaning up regkeys, just rename to "regkey"
        if node_type in ["regkey"]:
            g.vs[i]["name"] = "regkeys"

        # If executable, always just go with exe name
        #  whether its a file or a process
        if name.endswith(".exe"):
            name = name.split('\\')
            name = name[len(name)-1]
            g.vs[i]["name"] = name

        # Filter windows file paths to make them semi-salient
        #  and semi-collapsable, pure trial and error on these filters
        if node_type == "file" and '\\' in name:
            modified = False

            for prefix in winfile_prefix_filters:
                if prefix in name:
                    name = name.split(prefix)
                    name = name[len(name)-1]
                    
            for suffix in winfile_suffix_filters:
                if suffix in name:                
                    name = name[:name.index(suffix) + len(suffix)]
                    modified = True
            
            if not modified:
                name = name.split('\\')
                name = name[len(name)-1]

            g.vs[i]["name"] = name


    #######################################
    #      Edge relabels
    #######################################
    # Some syscalls in my input files started with "EVENT_", dropping that
    for j in range(0, len(g.es)):
        edge_type = g.es[j]["type"]
        if edge_type.startswith("EVENT_"):
            edge_type = edge_type.split("_")[1]
            g.es[j]["type"] = edge_type.lower()                
            
            
# Modify processes to denote UUIDs
#  (must be done later in processing than relabels())            
def mark_uuids(g):
    for i in range(0,len(g.vs)):
        if g.vs[i]["type"] == "process":
            g.vs[i]["name"] = g.vs[i]["name"]+":"+str(g.vs[i]["uuid"])[:4]

def get_seed_labels(seed_file):

    seed_labels={}
    if os.path.isfile(seed_file):
        # Read seed labels in from csv
        try:
            with open(seed_file,'r') as csvfile:
                rdr = csv.reader(csvfile, quotechar="\"")
                for row in rdr:
                    seed_labels[row[3]] = row[4]
        except Exception as e:
            print("Error: %s" % (e))
            pdb.set_trace()

    return seed_labels

def contaminate_graph(g, seed_file):

    seed_labels = get_seed_labels(seed_file)

    # Generate lists of root causes 
    root_vertex_ids = []
    for v in g.vs:
        i = v.index
        v_uuid = str(g.vs[i]["uuid"])
        if seed_labels[v_uuid] == "root_cause":                
            root_vertex_ids.append(g.vs[i].index)
                
    # Identify all descendents of root cause (incl.)
    descendents = []
    for r in root_vertex_ids:
        descendents = descendents + forward_trace(g, r, depth=0, timestamp=False, visited=[])

    # Mark descendents of contaminate sources as contaminated
    g.vs["contaminate_label"] = [False for n in g.vs["name"]]
    for d in descendents:
        g.vs[d]["contaminate_label"] = True            
    
# Color the graph
def color_graph(g, seed_file):

    seed_labels={}
    if os.path.isfile(seed_file):

        
        seed_labels = get_seed_labels(seed_file)

        g.vs["attack_label"] = [False for n in g.vs["type"]]
        g.es["attack_label"] = [False for n in g.es["type"]]
        
        g.vs["color"] = g.vs["type"]

        # Generate lists of root causes and impacts
        root_min = False
        impact_max = False
        root_vertex_ids = []
        impact_vertex_ids = []
        for v in g.vs:
            i = v.index
            v_uuid = str(g.vs[i]["uuid"])
            if seed_labels[v_uuid] == "root_cause":                
                root_vertex_ids.append(g.vs[i].index)
                if not root_min or root_min > g.vs[i]["min_time"]:
                    root_min = g.vs[i]["min_time"]
                
            elif seed_labels[v_uuid] == "impact":
                impact_vertex_ids.append(g.vs[i].index)
                if not impact_max or impact_max < g.vs[i]["max_time"]:
                    impact_max = g.vs[i]["max_time"]
            # Initial color
            g.vs["color"] = color_dict["default"]

        print("FT max time is %d, BT min time is %d" % (impact_max, root_min))
            
        # Propagate root cause taint in graph colors
        descendents = []
        print("Root Causes:")
        for r in root_vertex_ids:
            print_node(g,r,"")
            descendents = descendents + forward_trace(g, r, depth=0, timestamp=False, max_time=impact_max, visited=[])
        print("\t %d descendents" % (len(descendents)) )

        print("Impacts:")
        ancestors = []
        for i in impact_vertex_ids:
            print_node(g,i,"")
            ancestors = ancestors + backward_trace(g, i, depth=0, timestamp=False, min_time=root_min, visited=[])
        print("\t %d ancestors" % (len(ancestors)) )

        if len(descendents) > 0 and len(ancestors) > 0:
            attack_chain = [vertex for vertex in ancestors if vertex in descendents]
        '''
        elif len(ancestors) > 0:
            attack_chain = ancestors
        elif len(descendents) >0:
            attack_chain = descendents
        '''
        
        #print("%d descendents and %d ancestors, %d attack chain" % (len(descendents),
        #                                                            len(ancestors),
        #                                                            len(attack_chain)))
                                                                    
        # Color attack chain and mark attack_label attribute as True
        for d in attack_chain:
            vi = d
            v_uuid = str(g.vs[vi]["uuid"])
            g.vs[vi]["attack_label"] = True            
            if seed_labels[v_uuid] in ["root_cause", "impact", "contaminated"]:
                g.vs[vi]["color"] = color_dict[seed_labels[v_uuid]]
            elif g.vs[vi]["type"] != "unknown":
                g.vs[vi]["color"] = color_dict[g.vs[vi]["type"]]
            else:
                print("unknown in attack chain")
                print_node(g, vi)
                #pdb.set_trace()
                        
    # If there isn't a seed label csv, default to color vertex types
    else:
        g.vs["color"] = [color_dict[t] for t in g.vs["type"]]

# Color the graph
def sys_utils_only(g):

    system_utilites = ["explorer.exe"]
    
    # Identify sys utils
    sys_util_uuids = []
    for v in g.vs:
        i = v.index
        v_uuid = str(g.vs[i]["uuid"])
        v_label = str(g.vs[i]["name"])
        if v_label in  system_utilites:
            sys_util_uuids.append(v_uuid)
            g.vs[i]["attack_label"] = "sys_util"
            g.vs[i]["color"] = color_dict["root_cause"]
            
            for e in g.es.select(_source = i):
                
                # Processes only
                if g.vs[e.target]["type"] == "process":
                    g.vs[e.target]["attack_label"] = "one_hop"
                    if g.vs[e.target]["name"] not in system_utilites:
                        g.vs[e.target]["color"] = color_dict[g.vs[e.target]["type"]]
                        g.vs[e.target]["name"] = ""
                        
            for e in g.es.select(_target = i):

                # Processes only
                if g.vs[e.source]["type"] == "process":
                    g.vs[e.source]["attack_label"] = "one_hop"
                    if g.vs[e.source]["name"] not in system_utilites:
                        g.vs[e.source]["color"] = color_dict[g.vs[e.source]["type"]]
                        g.vs[e.source]["name"] = ""
                    
        
                
    # Delete Everything Else
    prune_set_v = []
    for v1 in g.vs:
        if not v1["attack_label"]:            
            prune_set_v.append(v1.index)
    g.delete_vertices(prune_set_v)

        
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

    
# Remove dangling vertices 
def prune_vertices(g, debug=False):

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
                # Or if v2 is part of the attack
                if v2.index in prune_set_v:
                    continue

                # Merge candidate if both are unknown
                # Merge candidate if both have same data entity name
                if( (v1["type"] == "unknown" and v2["type"] == "unknown")
                    or (v1["type"] in ["file", "socket", "regkey"]
                        and v2["type"] in ["file", "socket", "regkey"]
                        and v1["name"] == v2["name"])
                    or (v1["name"] == "" and v2["name"] == "" and
                        "process" not in  [v1["type"], v2["type"]]) ):

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
        if "time" in v.attributes():
            timestamps.append(v["time"])

    timestamps.sort()
        
    for e in g.es:
        e["time"] = timestamps.index(e["time"])

    for v in g.vs:
        if "time" in v.attributes():
            v["time"] = timestamps.index(v["time"])
            
# Find the minimum and maximum access times per vertex.
# used to scope graph traversals.
def vertex_times(g):

    g.vs["min_time"] = [0 for n in g.vs["name"]]
    g.vs["max_time"] = g.vs["min_time"]

    # All edges are assumed to have a "time" timestamp attribute
    # Some formats also have an "etime" end timestamp.
    # Mirror "time" into "etime" if "etime" doesn't exist.
    if "etime" not in g.es.attributes():
        g.es["etime"] = [t for t in g.es["time"]]

    for v in g.vs:
        min_time = False
        max_time = False
        try:
            for e in g.es.select(_source = v.index):
                
                if not min_time or e["time"] < min_time:
                    min_time = e["time"]                
                if not max_time or e["etime"] > max_time:
                    max_time = e["etime"]                    

            for e in g.es.select(_target = v.index):
                if not min_time or e["time"] < min_time:
                    min_time = e["time"]                
                    if not max_time or e["etime"] > max_time:
                        max_time = e["etime"]

        except Exception as error:
            print("An exception occurred:", type(error).__name__)
            print(e)
            print(traceback.format_exc())
            pdb.set_trace()
        v["min_time"] = min_time
        v["max_time"] = max_time
            
def attack_only(g):

    prune_set_v = []
    for v1 in g.vs:
        if not v1["attack_label"]:
            prune_set_v.append(v1.index)

    g.delete_vertices(prune_set_v)

    prune_set_e = []
    for e1 in g.es:
        if not e1["attack_label"]:
            prune_set_e.append(e1.index)

    g.delete_edges(prune_set_e)


def merge_excess_sockets(g, seed_file):

    seed_labels = get_seed_labels(seed_file)
    
    prune_set_e = []
    prune_set_v = []
    # Iterate over all nodes
    for v in g.vs:
        # Skip if v is already marked for deletion
        if v.index in prune_set_v:
            continue
        # Skip if this isn't a process
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

                # Merge candidate if both are sockets
                # and neither is a root cause or impact
                if( (v1["type"] == "socket" and v2["type"] == "socket")
                    and not (seed_labels[str(v1["uuid"])] in ["root_cause", "impact"]
                            or seed_labels[str(v2["uuid"])] in ["root_cause", "impact"]) ):
                        
                    node_to_keep = v1
                    v1["name"] = "*.*.*.*"
                    node_to_prune = v2
                    prune_set_v.append(v2.index)
                    
                    for e in g.es.select(_source = node_to_prune):                        
                        if e.index == node_to_keep.index:                        
                            continue
                        # If this edge is redundant, do not add a new edge
                        if len(g.es.select(_source = node_to_keep.index, _target=e.target)) == 0:
                            new_e = g.add_edge(node_to_keep.index, e.target)
                            new_e.update_attributes(e.attributes())
                        prune_set_e.append(e.index)

                    for e in g.es.select(_target = node_to_prune):
                        if e.index == node_to_keep.index:
                            continue
                        # If this edge is redundant, do not add a new edge
                        if len(g.es.select(_source = e.source, _target=node_to_keep.index)) == 0:
                            new_e = g.add_edge(e.source, node_to_keep.index)
                            new_e.update_attributes(e.attributes())
                        prune_set_e.append(e.index)


    g.delete_edges(prune_set_e)    
    g.delete_vertices(prune_set_v)

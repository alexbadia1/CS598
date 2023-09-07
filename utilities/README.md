These scripts are all designed to work on igraph exports of provenance graphs serialized and compressed as `pkl.xz` files. There are several vertex and edge attributes that must be present in order for them to work:

Vertices:

* TBA

Edges:

* TBA

Description of scripts:

* `graph_helpers.py`: Helper functions for manipulating provenance igraphs.
* `dump_igraph.py`: Outputs every provenance vertex and edge relationship in kinda-pretty format.
* `dump_vertices.py`: Outputs every provenance vertex in kinda-pretty format. Used to seed the `color_graph` function with root causes and impacts. Dump the vertices into a csv file with the same name as your igraph pkl.
* `igraph_to_viz.py`: Outputs cleaned up visualization of the provenance graph using the igraph plot function.
* `label_graph.py`: Basically does the same thing as the `igraph_to_viz.py` script but the output is the finalized labels instead of a visualization. Both scripts use the `color_graph` function to identify the attack graph from its root causes and impacts.

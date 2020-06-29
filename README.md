# Gallium: Automated Software Middlebox Offloading to Programmable Switches

This is the source code repository of the Gallium project.
Check out [our paper](https://conferences.sigcomm.org/sigcomm/2020/camera-ready.html) for more details

## Directory Structure

Subdirectory      | Description
------------------| ---------------
`compiler/`       | Source for the Gallium compiler
`extractor`       | Source for a vistualizer for dependency analysis and partitioning
`click-llvm-ir.tar.gz`       | Pre-compiled LLVM code for Click elements

## Build Instruction
### System Requirements
Gallium requires Boost(>= 1.65), LLVM and gtest(>= 1.10). The current version works with LLVM-9.0

#### Initialize Environment using Docker
```bash
git clone https://github.com/Kaiyuan-Zhang/Gallium-public
cd Gallium-public
docker build -t gallium .
docker run -it gallium
```
Now, we are inside the container, we need to clone the repo again
```bash
git clone https://github.com/Kaiyuan-Zhang/Gallium-public
cd Gallium-public
```

### Gallium Compiler
To build Galliums compiler:
```bash
cd compiler
mkdir build
cd build
cmake ..
```
Then run
```bash
make -j
```

## Using Gallium to partition a simple middlebox
Here is a quick walk through of Gallium's workflow using a simple NAT as the example. The code of the example middlebox is included in `examples/myrewriter.cc`.
### The Middlebox
Galliums currently works on the LLVM IR of Click's elements.
To prepare the IRs, run from project root directory
```bash
tar zxvf click-llvm-ir.tar.gz
```
Now go into `compiler/build` to proceed to the next step
```bash
cd compiler/build
```

### Gallium's High-level IR
The first step of Gallium's compilation is to reconstruct high-level packet & state operations from the LLVM IR. This process also inlines all the non recursive function calls. For our example middlebox, run
```bash
./example-hir > example.hir
```
Now you can open the generated `example.hir` file (with your favorate text editor) in the current directory to see Gallium's high-level IR representation of the middlebox.

### The Labeling Algorithm
The core component of Galliums is the labeling algorithm, which will assign labels to each operation in the high-level IR for further program partition. For our example, run
```bash
./example-labeling > example-labeled.hir
```
Now you can open the generated `example-labeled.hir` file (with your favorate text editor) in the current directory to see the result of the labeling algorithm. you will see each operation are assigned with one or more of the labels {PRE, CPU, POST}. For example the line:
```llvm
%39_0 = call HashMap<IPFlowID, MyIPRewriterEntry>::findp(IPFlowID const&) const  map_4 %5_0 @ {PRE, CPU}
```
shows that this loopup operation performed on the hashmap can only be put on either ingress program or the middlebox server, but not the egress program.

### Partitioning
With the labeling done, now we could partition the middlebox. Run
```bash
./example-partition
```
This will generate three files `part-ingress.hir`, `part-cpu.hir`, and `part-egress.hir`. Each contains the code for ingress, middlebox server, and egress stage.

### Code Gen
With the labeling done, now we could partition the middlebox. Run
```bash
./example-codegen
```
This will generate two files `offloaded.p4` and `cpu.c`.

### Source Code Structure
Here is a list of the correspondence between each of the aforementioned step and the source code files

Source Code                     | Components
------------------              | ---------------
`hilvl-ir.{hpp,cpp}`            | High-level IR (HIR)
`hir-partition.{hpp,cpp}`       | Labeling & Partitioning
`hir-dpdkgen{hpp,cpp}`          | Code Generation to C
`hir-p4.{hpp,cpp}`              | Compile HIR to Gallium's IR representation of P4
`p4-ir.{hpp,cpp}`               | Code Generation to P4

# checksecc
Not just a c rewrite.
## introduction
The checksecc is a c rewrite of checksec but has some highlights. It retains all the core functionality of checksec,you can operate on it just like the original.
## highlights
remote check:<br>
You can compile it on modern operating systems such as linux or win, and then check the remote linux host to facilitate further information gathering on a reverse ssl connect.<br>
C/C++ API:<br>
The checksecc provides a library and documentation to help you to do more flexible operation with this api.
## todo
We expect more modern operating systems to be included.
## Something
we removed some uncommon features and added some useful features.

char *command="for N in [1-9]*; do if [[ "${N}" != "$$" ]] && readlink -q /proc/"${N}"/exe > /dev/null; then echo $N; fi done";

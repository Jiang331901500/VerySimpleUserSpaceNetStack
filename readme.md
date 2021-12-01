# Before compiling
You should compile and install [netmap](https://github.com/luigirizzo/netmap).

# Compile
```
gcc *.c -o uns_demo             # with debug print
# or
gcc *.c -o uns_demo -DNO_DEBUG  # without debug print
```

# Run
Before running uns_demo, you should make sure that `netmap.ko` has been installed. It can be done through executing cmd below:
```
sudo insmod netmap.ko   # in root diretory of netmap src code
```

Start the demo by:
```
sudo ./uns_demo eth1    # or eth0 etc.
```

# Test

We can test the demo with some simple net-test tool like NetAssist.
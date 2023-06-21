# How to run `burpa` tests

First, set the required environment variables such that the burpa controller can connect to Burp Suite APIs:

```
export BURP_API_URL=""
export BURP_API_PORT=""
export BURP_NEW_API_URL=""
export BURP_NEW_API_PORT=""
export BURP_NEW_API_KEY=""
```

Make sure your Burp Suite server is up and running. 

Change directory to `./tests/` and run the following in order to install BATS test system. 

```
git clone https://github.com/bats-core/bats-core.git
cd bats-core && ./install.sh $HOME && cd ..
git clone https://github.com/ztombol/bats-support
git clone https://github.com/ztombol/bats-assert
```

Run tests by calling

```
./runtests.sh
```


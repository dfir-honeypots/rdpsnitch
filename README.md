# RDP Snitch

A script to call out RDP scanners seen in the wild. This bot depends on Moloch
loading PCAP data in Elasticsearch for the queries. You will also need to set
up Pastebin and Twitter accounts with API access to post the resulting data
automatically.

This is the code that powers [@RDPSnitch](https://twitter.com/RdpSnitch).

## Setting up

You can run this script either within a docker container or in another
environment that uses Python3.

In both situations you'll need to set up the following accounts:
* Pastebin account for the script to post data to, with API access.
* Twitter account for the script to post tweets to, with approved API access.

### Docker

This project leverages docker to make execution easier, though it still requires
a few steps to get running

1. Clone the respository to your local machine
2. Edit the `constants-template.py` to add the corresponding values for all of
   the variables. Save as `constants.py`.
3. Build the docker container using: `docker build -t rdpsnitch:latest .`
4. Execute the docker container: `docker run rdpsnitch:latest`

### In your own environment

To run this in your own environment, you will need to run through a few more
steps:

1. Clone the respository to your local machine
2. Edit the `constants-template.py` to add the corresponding values for all of
   the variables. Save as `constants.py`.
3. Install Python3 and ensure `pip3` is available
4. Set up a virtual environment by running `pip3 install virtualenv`, create
   the environment with `virtualenv -p python3 venv`, and then activate the
   virtual environment.
5. Run `pip install -r requirements.txt`
6. Execute the script `python rdp-snitch.py`


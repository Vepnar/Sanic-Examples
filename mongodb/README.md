# Requirement with docker. (recommended)
First you need docker, python 3.7.<br>
`apt-get install docker python3.7 mongodb`

Now you need pip for Python 3.7. <br>
`python3.7 -m pip install pip`

Now you need to install docker-compose in pip. <br>
`python3.7 -m pip install docker-compose`

After that we need to build our docker container.<br>
`docker-compose build`

And now to run it.<br>
`docker-compose up`

# Requirements without docker.
First you need Python 3.7 and mongodb.<br>
`apt-get install python3.7 mongodb`

Now you need pip for Python 3.7.<br>
`python3.7 -m pip install pip`

After that you install the requirements for this application.<br>
`python3.7 -m pip install -r requirements.txt`

Now you should be able to execute this application.<br>
`python3.7 main.py`

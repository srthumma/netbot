!/bin/bash
export HOME=/home/netbot

cd $HOME/netbot
#run python script with virtual env
source venv/bin/activate
python3 netbot.py
deactivate


ps -ef|grep volatility_monitor_server|grep -v grep|cut -c 9-15|xargs kill -9
ps -ef|grep vol.py|grep -v grep|cut -c 9-15|xargs kill -9
ps -ef|grep dump|grep -v grep|cut -c 9-15|xargs kill -9



rm files/*
cat /dev/null > nohup.out
(nohup python filesystem_monitor_server.py &)

#Here is the  commands  that I used to compile the code on the remote machine.

remoteusr@bsdhost:~/test $ gcc -o data_daemon data_daemon.c -lssl -lcrypto -lpthread
remoteusr@bsdhost:~/test $ ./data_daemon
remoteusr@bsdhost:~/test $


remoteusr@bsdhost:~/test $ gcc -c libdata.c -o libdata.o -lssl -lcrypto
remoteusr@bsdhost:~/test $ gcc client.c libdata.o -o client -lssl -lcrypto
remoteusr@bsdhost:~/test $ ./client

remoteusr@bsdhost:~/test $ gcc -o client_lastupdate client_lastupdate.c libdata.c -lcrypto
remoteusr@bsdhost:~/test $ ./client_lastupdate
Usage: ./client_lastupdate <ID> <secret>
remoteusr@bsdhost:~/test $ ./client_lastupdate 001 001
Last update time for '001': Fri Mar 21 20:36:13 2025
remoteusr@bsdhost:~/test $

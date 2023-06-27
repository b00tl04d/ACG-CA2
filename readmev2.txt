1. Run 2 separate terminal
2. CD to the server directory (using terminal 1) under source directory
   2.1  Server directory should contain server.py and menu_today.txt files
3. Type "python server.py"
   3.1  You should see:-
	a.   Socket Created
        b.   Socket bind complete
        c.   Socket now listening
   	Your server program is successfully setup and is 
        listening for connection now
4. CD to the client directory (using terminal 2) under source directory
   4.1  Client directory should contain client.py and
        day_end.csv files
5. Type "python client.py"
   5.1  You should see:-
	a. Menu today received from server
   	b. Sale of the day sent to server
   5.2  menu.csv recevied by client
   5.3  Connection terminated and back to command prompt
6. File "result-<IP Address>" received by server



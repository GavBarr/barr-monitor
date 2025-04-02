This is a command line tool (specifically for windows only for now) that can monitor logging directories. Specifically it will monitor for any files .txt or .log. It is monitoring specifially for issues within the log files, keywords that are looked for are
"ERROR", "WARNING" and "CRITICAL". You can set the process do be ran in the background and perform checks in time increments, or perform a one time check. There is also the ability to ouput what is found to a file that you specify.

Examples:
  barr-monitor logs                         #this will perform an instant/one time monitor for the logs directory
  barr-monitor logs --watch 5 report.txt    #this will perform a monitor in 5 minute increments and then write what is found to the .txt file

  barr-monitor listing                      #this will show any and all running barr-monitor processes
  barr-monitor stop {PID}                   #this will stop the current process ID that is provided
  

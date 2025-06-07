#deploy_timesketch_expect.sh

#!/usr/bin/expect -f

set timeout -1

spawn sudo /opt/deploy_timesketch.sh

expect {
    "Would you like to start the containers?" {
        send "Y\r"
    }
    timeout {
        puts "Timeout waiting for the first question"
        exit 1
    }
}

expect {
    "Would you like to create a new timesketch user" {
        send "N\r"
    }
    timeout {
        puts "Timeout waiting for the second question"
        exit 1
    }
}

expect eof

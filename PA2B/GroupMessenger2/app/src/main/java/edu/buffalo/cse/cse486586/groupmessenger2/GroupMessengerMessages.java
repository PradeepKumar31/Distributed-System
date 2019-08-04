package edu.buffalo.cse.cse486586.groupmessenger2;

import java.io.Serializable;

public class GroupMessengerMessages implements Serializable, Comparable<GroupMessengerMessages> {
    String port;
    String msg;
    int msg_sequence;
    boolean can_deliver;

    public GroupMessengerMessages(String port, String msg, int msg_sequence, boolean can_deliver) {
        this.port = port;
        this.msg = msg;
        this.msg_sequence = msg_sequence;
        this.can_deliver = can_deliver;
    }

    @Override
    public int compareTo(GroupMessengerMessages anotherClient) {
        if (msg_sequence < anotherClient.msg_sequence)
            return -1;
        else if (msg_sequence > anotherClient.msg_sequence)
            return 1;
        else {
            if (Integer.parseInt(port) < Integer.parseInt(anotherClient.port))
                return -1;
            else
                return 1;
        }
    }
}

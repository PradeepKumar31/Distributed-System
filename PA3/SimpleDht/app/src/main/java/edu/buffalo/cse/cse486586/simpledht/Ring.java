package edu.buffalo.cse.cse486586.simpledht;

import android.util.Log;

import org.w3c.dom.Node;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

public class Ring {
    String nodeID;
    String predecessor;
    String successor;

    @Override
    public String toString() {
        return "Node{" +
                "nodeID='" + nodeID + '\'' +
                ", predecessor='" + predecessor + '\'' +
                ", successor='" + successor + '\'' +
                '}';
    }

    public String getID() {
        try {
            return genHash(nodeID);
        } catch (Exception exception){
            Log.e("Pradeep_Node", exception.getMessage());
        }
        return null;
    }

    public String getBackNode() {
        try {
            return genHash(predecessor);
        } catch (Exception exception) {
            Log.e("Pradeep_Node", exception.getMessage());
        }
        return null;
    }

    public String getFrontNode() {
        try {
            return genHash(successor);
        } catch (Exception exception) {
            Log.e("Pradeep_Node", exception.getMessage());
        }
        return null;
    }

    private boolean verify(String id, Ring ring) {
        BigInteger idVal = new BigInteger(id, 16);
        BigInteger maxNodeVal = new BigInteger(SimpleDhtProvider.MAXIMUM_HASH, 16);
        BigInteger nodeVal = new BigInteger(ring.getID(), 16);
        BigInteger successorVal = new BigInteger(ring.getFrontNode(), 16);

        if ((idVal.compareTo(nodeVal) > 0 && idVal.compareTo(successorVal) <= 0)
            || (idVal.compareTo(nodeVal) > 0 && idVal.compareTo(successorVal) > 0 && nodeVal.compareTo(successorVal) > 0)
            || (idVal.compareTo(nodeVal) < 0 && idVal.compareTo(successorVal) < 0 && nodeVal.compareTo(successorVal) > 0)
            || (nodeVal.compareTo(maxNodeVal) == 0 && idVal.compareTo(nodeVal) < 0 && idVal.compareTo(successorVal) < 0) ) {
            return true;
        }
        else {
            return false;
        }
    }

    public Ring findBackNode(String id) {
        Ring ring = this;

        try {
            while (!verify(genHash(id), ring)) {
                Socket client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(ring.successor)*2);

                Log.i("Pradeep_Node", "Getting node : " + ring.successor);

                PrintWriter msgSend = new PrintWriter(client.getOutputStream(), true);
                BufferedReader ackGet = new BufferedReader(new InputStreamReader(client.getInputStream()));
                msgSend.println("Data_Node");

                while (!client.isClosed()) {
                    String ack = ackGet.readLine();

                    if(ack.contains("Node_Data")) {
                        ring = new Ring();
                        String[] rcvNode = ack.split(":");
                        ring.nodeID = rcvNode[1];
                        ring.predecessor = rcvNode[2];
                        ring.successor = rcvNode[3];

                        client.close();
                    }
                }
            }
        } catch (Exception exception) {
            Log.e("Pradeep_Node", exception.getMessage());
        }
        return ring;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }
}
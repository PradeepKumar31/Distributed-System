package edu.buffalo.cse.cse486586.groupmessenger2;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.PriorityQueue;

/**
 * GroupMessengerActivity is the main Activity for the assignment.
 *
 * @author stevko
 *
 */
public class GroupMessengerActivity extends Activity {
    static final String TAG = GroupMessengerActivity.class.getSimpleName();
    static final int SERVER_PORT = 10000;

    /*
    * It will store all the 5 port numbers
    * */
    static ArrayList<String> PORTS = new ArrayList<String>();

    /*
    * Here we will store the all the messages as a class object where we are using
    * compareTo function to sort based on sequence number, if that equals than based on deliverable
    * and if that is equals too then based on the port number.
    * */
    static PriorityQueue<GroupMessengerMessages> messageQueue = new PriorityQueue<GroupMessengerMessages>();

    /*
    * Storing messages based on the global variable AGREED_SEQUENCE. This will be the final sequence
    * number.
    * */
    static int AGREED_SEQUENCE = -1;

    /*
    * Here we will store the failed port to keep a track of it and remove it from the list and delete
    * all the messages which can not be delivered for that port
    * */
    static String FAILED = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_group_messenger);

        /*
         * TODO: Use the TextView to display your messages. Though there is no grading component
         * on how you display the messages, if you implement it, it'll make your debugging easier.
         */

        TelephonyManager tel = (TelephonyManager) this.getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        final String myPort = String.valueOf((Integer.parseInt(portStr) * 2));

        /*
        * Here we are adding all the ports to the list
        * */
        PORTS.add("11108");
        PORTS.add("11112");
        PORTS.add("11116");
        PORTS.add("11120");
        PORTS.add("11124");

        try {
            /*
             * Create a server socket as well as a thread (AsyncTask) that listens on the server
             * port.
             *
             * AsyncTask is a simplified thread construct that Android provides. Please make sure
             * you know how it works by reading
             * http://developer.android.com/reference/android/os/AsyncTask.html
             */
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            /*
             * Log is a good way to debug your code. LogCat prints out all the messages that
             * Log class writes.
             *
             * Please read http://developer.android.com/tools/debugging/debugging-projects.html
             * and http://developer.android.com/tools/debugging/debugging-log.html
             * for more information on debugging.
             */
            Log.e(TAG, "Can't create a ServerSocket");
            return;
        }

        TextView tv = (TextView) findViewById(R.id.textView1);
        tv.setMovementMethod(new ScrollingMovementMethod());

        /*
         * Registers OnPTestClickListener for "button1" in the layout, which is the "PTest" button.
         * OnPTestClickListener demonstrates how to access a ContentProvider.
         */
        findViewById(R.id.button1).setOnClickListener(
                new OnPTestClickListener(tv, getContentResolver()));

        /*
         * TODO: You need to register and implement an OnClickListener for the "Send" button.
         * In your implementation you need to get the message from the input box (EditText)
         * and send it to other AVDs.
         */
        final Button sendButton = (Button) findViewById(R.id.button4);
        sendButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText editText = (EditText) findViewById(R.id.editText1);
                String msg = editText.getText().toString();
                editText.setText("");

                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, myPort);
            }
        });
    }

    /**
     * buildUri() demonstrates how to build a URI for a ContentProvider.
     *
     * @param scheme
     * @param authority
     * @return the URI
     */
    private Uri buildUri(String scheme, String authority) {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority(authority);
        uriBuilder.scheme(scheme);
        return uriBuilder.build();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.activity_group_messenger, menu);
        return true;
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];

            /*
            * Variable to hold the sequence number for initial allocation.
            * */
            int sequence = -1;

            try {
                while (true) {
                    /*
                    * Server Socket is created and waiting for client connection to create.
                    * Reader and writer objects are created for accepting and sending messages between
                    * server and clients.
                    * */
                    Socket client = serverSocket.accept();
                    ObjectInputStream reader = new ObjectInputStream(client.getInputStream());
                    PrintWriter printWriter = new PrintWriter(client.getOutputStream(), true);
                    GroupMessengerMessages groupMessengerMessages = (GroupMessengerMessages) reader.readObject();

                    if (groupMessengerMessages.msg != null) {
                        if (!groupMessengerMessages.can_deliver) {
                            Log.d("Pradeep1111: ", sequence + ", " + AGREED_SEQUENCE);

                            /*
                            * Initially when we are adding messages to the queue with delivery status
                            * as false then we are finalizing the sequence of the message, by comparing
                            * the AGREED_SEQUENCE i.e. the final sequence for the message and sequence
                            * to get the larger number and increase it by 1.
                            * */
                            if (AGREED_SEQUENCE > sequence)
                                sequence = 1 + AGREED_SEQUENCE;
                            else
                                sequence = 1 + sequence;

                            Log.d("Pradeep11112: ", sequence + ", " + AGREED_SEQUENCE);

                            messageQueue.add(groupMessengerMessages);
                            printWriter.println("" + sequence);
                        }
                        else {
                            for (GroupMessengerMessages message : messageQueue) {
                                Log.d("Pradeep14555: ", message.msg);
                                if (message.msg.equals(groupMessengerMessages.msg)) {
                                    /*
                                    * We remove the message with status false for that particular message
                                    * in the Queue.
                                    * */

                                    Log.d("Pradeep11114: ", groupMessengerMessages.msg);
                                    messageQueue.remove(message);
                                    break;
                                }
                            }

                            if ( !groupMessengerMessages.port.equals(FAILED) ) {
                                Log.d("Pradeep1788: ", groupMessengerMessages.port);
                                /*
                                * We are adding the message object with the agreed sequence number and
                                * with status as true i.e. ready to deliver
                                * */

                                messageQueue.add(new GroupMessengerMessages(groupMessengerMessages.port, groupMessengerMessages.msg,
                                        groupMessengerMessages.msg_sequence, true));
                            }
                        }

                        GroupMessengerMessages messengerMessages = null;
                        while ((messengerMessages = messageQueue.peek()) != null &&
                                messengerMessages.can_deliver) {

                            /*
                            * We will increase the sequence of message getting published to the clients.
                            * */
                            AGREED_SEQUENCE += 1;

                            Log.d("Pradeep184: ", AGREED_SEQUENCE + ", " + messengerMessages.msg +
                                    ", " + messengerMessages.msg_sequence);

                            publishProgress(AGREED_SEQUENCE + "," +
                                    messengerMessages.msg);
                            messageQueue.remove();
                        }

                        if ((messengerMessages = messageQueue.peek()) != null &&
                                !messengerMessages.can_deliver &&
                                messengerMessages.port.equals(FAILED)) {

                            /*
                            * We are deleting all the messages from the queue for the failed port with
                            * delivery status as false.
                            * */
                            messageQueue.remove(messengerMessages);
                            Log.d("Pradeep_4: ", messengerMessages.msg + ", "
                                    + messengerMessages.port + ", " +
                                    messengerMessages.msg_sequence);
                        }
                    }
                }
            } catch (Exception exception) {
                Log.e(TAG, exception.getMessage());
            }
            return null;
        }

        @Override
        protected void onProgressUpdate(String... strings) {
            super.onProgressUpdate(strings);
            String sequence = strings[0].split(",")[0];
            String strReceived = strings[0].split(",")[1];

            /*
            * Here we are storing all the message and key value in ContentProvider and displaying it
            * on the screen of AVD's.
            * */
            Log.d("Pradeep_4: ", sequence + ", " + strReceived);

            ContentResolver contentResolver = getContentResolver();
            Uri uri = buildUri("content", "edu.buffalo.cse.cse486586.groupmessenger2.provider");
            ContentValues contentValues = new ContentValues();
            contentValues.put("key", sequence);
            contentValues.put("value", strReceived);
            contentResolver.insert(uri, contentValues);

            TextView textView = (TextView) findViewById(R.id.textView1);
            textView.append("Message : "+ sequence + "\n");
        }
    }


    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... params) {
            int process_sequence = -1;
            ObjectOutputStream msgSend;

            for (String remote_port : PORTS) {
                try {
                    Log.d("Pradeep: ", remote_port);

                    /*
                    * Here we are creating client object and connecting with the server and setting
                    * timeout for the connection.
                    * */

                    Socket client = new Socket();
                    client.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(remote_port)));

                    Log.d("Pradeep: ", remote_port);

                    client.setSoTimeout(500);

                    msgSend = new ObjectOutputStream(client.getOutputStream());
                    BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));

                    Log.d("Pradeep: ", params[1] + ", " + params[0] + ", " + false);

                    msgSend.writeObject(new GroupMessengerMessages(params[1], params[0],
                            0, false));

                    String sequence = reader.readLine();
                    process_sequence = Integer.parseInt(sequence);

                    Log.d("Pradeep: ", sequence + ", " + process_sequence);

                    Thread.sleep(300);
                } catch(SocketTimeoutException ste){
                    Log.e(TAG, "SocketTimeout Exception : " + remote_port);
                    //FAILED = remote_port;

                    //Log.d("Pradeep_211: ", FAILED + ":" + remote_port);
                } catch(SocketException socketException){
                    Log.e(TAG, "Socket Exception : " + remote_port);
                    FAILED = remote_port;

                    Log.d("Pradeep_212: ", FAILED + ":" + remote_port);
                } catch (IOException ioException) {
                    Log.e(TAG, "IOException : " + remote_port);
                    FAILED = remote_port;

                    Log.d("Pradeep_213: ", FAILED + ":" + remote_port);
                } catch (NullPointerException nullPointerException) {
                    Log.e(TAG, "Null Pointer Exception : " + remote_port);
                    //FAILED = remote_port;

                    //Log.d("Pradeep_214: ", FAILED + ":" + remote_port);
                } catch (Exception exception) {
                    Log.e("Seq Num", exception.getMessage());
                }
            }

            for (String remote_port : PORTS) {
                try {
                    Log.d("Pradeep_1: ", remote_port);
                    Socket client = new Socket();
                    client.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(remote_port)));

                    Log.d("Pradeep_1: ", remote_port);

                    client.setSoTimeout(500);

                    msgSend = new ObjectOutputStream(client.getOutputStream());

                    Log.d("Pradeep_1: ", params[1] + ", " + params[0] + ", " +
                            process_sequence + ", " + true);

                    msgSend.writeObject(new GroupMessengerMessages(params[1], params[0],
                            process_sequence, true));

                    Thread.sleep(300);
                } catch(SocketTimeoutException ste){
                    Log.e(TAG, "SocketTimeout Exception : " + remote_port);
                    //FAILED = remote_port;

                    //Log.d("Pradeep_21: ", FAILED + ":" + remote_port);
                } catch(SocketException socketException){
                    Log.e(TAG, "Socket Exception : " + remote_port);
                    FAILED = remote_port;

                    Log.d("Pradeep_22: ", FAILED + ":" + remote_port);
                } catch (IOException ioException) {
                    Log.e(TAG, "IOException : " + remote_port);
                    FAILED = remote_port;

                    Log.d("Pradeep_23: ", FAILED + ":" + remote_port);
                } catch (NullPointerException nullPointerException) {
                    Log.e(TAG, "Null Pointer Exception : " + remote_port);
                    //FAILED = remote_port;

                    //Log.d("Pradeep_24: ", FAILED + ":" + remote_port);
                } catch (Exception exception) {
                    Log.e("Seq Num", exception.getMessage());
                }
            }

            if (PORTS.contains(FAILED))
            {
                Log.d("Pradeep_3: ", FAILED);
                PORTS.remove(FAILED);
                Log.d("Pradeep_3: ", PORTS.toString());
            }
            return null;
        }
    }
}